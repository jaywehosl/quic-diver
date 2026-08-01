// Package store хранит журнал операций на диске и держит собранное из него состояние.
//
// Разделение обязанностей простое: oplog знает правила, store знает диск. Всё, что можно
// проверить без базы, проверяется в oplog и там же покрыто тестами.
//
// # Порядок применения при восстановлении
//
// Записи применяются в том порядке, в каком узел их принял, — для этого у каждой есть
// локальный номер seq. Причина в причинности: операция оператора законна только после
// записи, выдавшей ему права. Сортировка по (ключ, счётчик) выглядит очевидной и ломает
// ровно это — при неудачном соседстве идентификаторов операции нового ключа поехали бы
// применяться раньше, чем ключ появился.
//
// Порядок seq у разных узлов свой, и это не мешает: конфликты правок разрешаются по времени
// записи, а не по порядку получения, что доказано тестами в oplog.
package store

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/jaywehosl/quic-diver/internal/oplog"
	_ "modernc.org/sqlite"
)

const schemaVersion = 1

// Store — журнал на диске плюс состояние в памяти.
type Store struct {
	db *sql.DB
	// expect — отпечаток сети, к которой мы принадлежим. Нулевой означает «любая»: так
	// открывается база администратора, где сеть только рождается.
	expect oplog.Fingerprint

	mu    sync.RWMutex
	state *oplog.State
	// changed закрывается на каждом изменении журнала и заменяется новым. Так ждущий
	// узнаёт о правке сразу, а молчащий журнал никого не будит.
	changed chan struct{}
}

var (
	ErrWrongNetwork  = errors.New("store: журнал принадлежит другой сети")
	ErrSchemaTooNew  = errors.New("store: база сделана более новой версией")
	ErrAlreadyExists = errors.New("store: такая запись уже есть")
)

// Open открывает или создаёт базу и восстанавливает из неё состояние.
//
// Если expect не нулевой, отпечаток сети обязан совпасть — и у журнала, уже лежащего в базе,
// и у любого генезиса, который в неё придёт потом. Так узел не примет за своё чужой журнал:
// ни случайно оказавшийся в том же файле, ни залитый посторонним по сети.
func Open(path string, expect oplog.Fingerprint) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: открытие базы: %w", err)
	}
	// Одно соединение: пишем мы всё равно под своим мьютексом, а SQLite на нескольких
	// соединениях начинает отдавать SQLITE_BUSY на ровном месте.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, expect: expect, state: oplog.NewState(), changed: make(chan struct{})}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.reload(); err != nil {
		db.Close()
		return nil, err
	}
	if !expect.IsZero() && !s.state.Genesis().IsZero() && s.state.Genesis() != expect {
		db.Close()
		return nil, fmt.Errorf("%w: в базе %s, ожидался %s", ErrWrongNetwork, s.state.Genesis(), expect)
	}
	return s, nil
}

func (s *Store) init() error {
	pragmas := []string{
		// Журнал дописывается по одной записи и читается целиком при старте — WAL здесь
		// и быстрее, и переживает падение процесса без потери последней записи.
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = FULL`,
		`PRAGMA foreign_keys = ON`,
	}
	for _, p := range pragmas {
		if _, err := s.db.Exec(p); err != nil {
			return fmt.Errorf("store: %s: %w", p, err)
		}
	}

	const schema = `
CREATE TABLE IF NOT EXISTS meta (
	k TEXT PRIMARY KEY,
	v TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS ops (
	seq     INTEGER PRIMARY KEY AUTOINCREMENT,
	key_id  BLOB    NOT NULL,
	counter INTEGER NOT NULL,
	kind    INTEGER NOT NULL,
	ts      INTEGER NOT NULL,
	effect  TEXT    NOT NULL,
	raw     BLOB    NOT NULL,
	UNIQUE (key_id, counter)
) STRICT;

CREATE INDEX IF NOT EXISTS ops_by_key ON ops (key_id, counter);
` + usageSchema
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("store: создание схемы: %w", err)
	}

	var got string
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k = 'schema_version'`).Scan(&got)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = s.db.Exec(`INSERT INTO meta (k, v) VALUES ('schema_version', ?)`, fmt.Sprint(schemaVersion))
		if err != nil {
			return fmt.Errorf("store: запись версии схемы: %w", err)
		}
	case err != nil:
		return fmt.Errorf("store: чтение версии схемы: %w", err)
	default:
		var v int
		if _, err := fmt.Sscanf(got, "%d", &v); err != nil {
			return fmt.Errorf("store: непонятная версия схемы %q", got)
		}
		if v > schemaVersion {
			return fmt.Errorf("%w: версия %d, эта сборка умеет %d", ErrSchemaTooNew, v, schemaVersion)
		}
	}
	return nil
}

// loadState собирает состояние из того, что лежит в базе. Мьютекс не трогает —
// вызывается и при открытии, и из-под уже взятой блокировки.
func (s *Store) loadState() (*oplog.State, error) {
	rows, err := s.db.Query(`SELECT raw FROM ops ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("store: чтение журнала: %w", err)
	}
	defer rows.Close()

	state := oplog.NewState()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("store: чтение записи: %w", err)
		}
		op, err := oplog.Decode(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("store: разбор записи из базы: %w", err)
		}
		if _, err := state.Apply(op); err != nil {
			// Записи в базу попадают только через Append, то есть уже проверенными.
			// Осечка здесь означает порчу файла, а не негодную запись, и молчать о ней нельзя.
			return nil, fmt.Errorf("store: журнал не сходится на записи %s/%d: %w", op.Key, op.Counter, err)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: обход журнала: %w", err)
	}
	return state, nil
}

// reload пересобирает состояние из журнала.
func (s *Store) reload() error {
	state, err := s.loadState()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.state = state
	s.mu.Unlock()
	return nil
}

// Append проверяет запись, применяет её к состоянию и сохраняет.
//
// Порядок именно такой: проверка и применение живут в oplog, и только прошедшая их запись
// достойна места в базе. Обратный порядок означал бы, что чужой мусор занимает диск.
func (s *Store) Append(op *oplog.Op) (oplog.Effect, error) {
	raw, err := op.Bytes()
	if err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Генезис — единственная запись, которую проверить подписью недостаточно: она сама
	// объявляет ключи владельцев, поэтому любая правильно собранная чужая запись пройдёт
	// проверку подписи с блеском. Единственное, что отличает свою сеть от чужой, — отпечаток
	// из конфига. Сверяется он именно здесь, а не только при открытии базы: пустой узел
	// принимает первый залив от кого угодно (решение 007 §3.3), и вся защита держится на этой
	// строке.
	if op.Kind == oplog.KindGenesis && !s.expect.IsZero() {
		fp, err := oplog.FingerprintOf(op)
		if err != nil {
			return 0, err
		}
		if fp != s.expect {
			return 0, fmt.Errorf("%w: у записи %s, ожидался %s", ErrWrongNetwork, fp, s.expect)
		}
	}

	effect, err := s.state.Apply(op)
	if err != nil {
		return 0, err
	}

	_, err = s.db.Exec(
		`INSERT INTO ops (key_id, counter, kind, ts, effect, raw) VALUES (?, ?, ?, ?, ?, ?)`,
		op.Key[:], int64(op.Counter), int64(op.Kind), op.Time.UnixMilli(), effect.String(), raw,
	)
	if err != nil {
		// Состояние в памяти уже изменено, а на диск запись не легла — дальше доверять
		// памяти нельзя. Пересобираем её из того, что действительно сохранено.
		state, reloadErr := s.loadState()
		if reloadErr != nil {
			return 0, fmt.Errorf("store: запись не сохранена (%v) и состояние не восстановлено: %w", err, reloadErr)
		}
		s.state = state
		s.announce()
		return 0, fmt.Errorf("store: сохранение записи: %w", err)
	}
	s.announce()
	return effect, nil
}

// Changed отдаёт канал, который закроется на следующем изменении журнала.
//
// Ждущий берёт канал, ждёт его закрытия и берёт новый. Опрос по таймеру для того же не
// годится: правило, поменянное администратором, обязано доехать до клиента за секунды, а
// молчащий журнал не должен стоить ничего.
func (s *Store) Changed() <-chan struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.changed
}

// announce будит всех, кто ждёт изменений. Зовётся под уже взятой блокировкой записи.
func (s *Store) announce() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// State отдаёт текущее состояние.
//
// Возвращается сам объект, а не копия: копирование состояния на каждый запрос вышло бы
// заметно дороже, чем польза. Менять его снаружи нельзя — только читать.
func (s *Store) State() *oplog.State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// Counters говорит, что у нас есть по каждому ключу. С этого начинается обмен с соседом.
func (s *Store) Counters() map[oplog.KeyID]uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Counters()
}

// Since отдаёт записи, которых нет у собеседника, в порядке их применения у нас.
//
// have — счётчики собеседника: ключ и последняя запись, которая у него есть. Ключи, о которых
// он не знает вовсе, отдаются с самого начала.
func (s *Store) Since(have map[oplog.KeyID]uint64) ([]*oplog.Op, error) {
	rows, err := s.db.Query(`SELECT key_id, counter, raw FROM ops ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("store: выборка журнала: %w", err)
	}
	defer rows.Close()

	var out []*oplog.Op
	for rows.Next() {
		var (
			keyID   []byte
			counter int64
			raw     []byte
		)
		if err := rows.Scan(&keyID, &counter, &raw); err != nil {
			return nil, fmt.Errorf("store: чтение записи: %w", err)
		}
		var id oplog.KeyID
		copy(id[:], keyID)
		if uint64(counter) <= have[id] {
			continue
		}
		op, err := oplog.Decode(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("store: разбор записи: %w", err)
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

// Export выгружает журнал целиком — это и есть бэкап.
//
// Подделать его нельзя: каждая запись подписана, а первой идёт генезис, чей отпечаток узел
// сверяет с тем, что записан у него в конфиге. Поэтому бэкап не требует доверия ни к
// носителю, ни к тому, кто его принёс.
func (s *Store) Export(w io.Writer) error {
	rows, err := s.db.Query(`SELECT raw FROM ops ORDER BY seq`)
	if err != nil {
		return fmt.Errorf("store: выгрузка журнала: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return fmt.Errorf("store: чтение записи: %w", err)
		}
		if _, err := w.Write(raw); err != nil {
			return fmt.Errorf("store: запись выгрузки: %w", err)
		}
	}
	return rows.Err()
}

// Import вливает выгруженный журнал.
//
// Каждая запись проходит те же проверки, что и пришедшая по сети: подпись, права, место в
// последовательности. Файл, собранный кем угодно, не даст ничего, кроме отказа.
//
// Вливание идемпотентно: то, что у нас уже есть, пропускается молча. Иначе повторная
// раскатка бэкапа падала бы на первой же записи, а обмен с соседом — на каждом круге, ведь
// сосед присылает и то, что мы давно применили. Возвращается число именно новых записей.
func (s *Store) Import(r io.Reader) (int, error) {
	added, seen := 0, 0
	for {
		op, err := oplog.Decode(r)
		if errors.Is(err, io.EOF) {
			return added, nil
		}
		if err != nil {
			return added, fmt.Errorf("store: разбор выгрузки на записи %d: %w", added+seen+1, err)
		}

		switch _, err := s.Append(op); {
		case err == nil:
			added++
		case errors.Is(err, oplog.ErrReplay), errors.Is(err, oplog.ErrDoubleGenesis):
			// Уже применяли. Для генезиса это ещё и проверка совпадения сети: чужой
			// генезис отличался бы отпечатком, и его запись не совпала бы с нашей.
			if op.Kind == oplog.KindGenesis {
				fp, ferr := oplog.FingerprintOf(op)
				if ferr != nil {
					return added, ferr
				}
				if fp != s.State().Genesis() {
					return added, fmt.Errorf("%w: в файле %s, у нас %s", ErrWrongNetwork, fp, s.State().Genesis())
				}
			}
			seen++
		default:
			return added, fmt.Errorf("store: запись %d из выгрузки: %w", added+seen+1, err)
		}
	}
}

// Len возвращает число записей в журнале.
func (s *Store) Len() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM ops`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: подсчёт записей: %w", err)
	}
	return n, nil
}

// Close закрывает базу.
func (s *Store) Close() error { return s.db.Close() }
