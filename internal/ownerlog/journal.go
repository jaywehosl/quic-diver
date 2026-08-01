// Package ownerlog — журнал сети в руках владельца.
//
// # Чем отличается от internal/store
//
// Ничем по смыслу и всем по устройству. Store — это SQLite: индексы, транзакции, выборки по
// счётчикам, живучесть при падении посреди записи. Узлу это нужно: он держит журнал годами,
// сверяется с десятком соседей и обязан пережить выключение питания в любой момент.
//
// Владельцу нужно другое. Журнал у него на телефоне, записей в нём десятки, и открывает он его
// раз в неделю — добавить клиента или узел. Тащить ради этого SQLite в мобильную сборку
// означало бы несколько мегабайт кода, который на телефоне почти не выполняется.
//
// Поэтому здесь журнал — то, чем он и является по определению: последовательность записей.
// Лежит одним файлом, читается целиком, состояние собирается прогоном через oplog.State — тем
// же кодом, каким его собирает узел. Формат байт в байт совпадает с выгрузкой store.Export,
// поэтому журнал владельца можно залить в узел, а выгрузку узла — открыть у владельца.
//
// # Чего здесь нет
//
// Сверки с соседями (это дело узлов), отбора записей по счётчикам (для десятков записей проще
// отдать всё) и защиты от одновременной записи из двух процессов (владелец один, и он на своём
// устройстве).
package ownerlog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// maxJournal ограничивает размер читаемого журнала.
//
// Журнал владельца — это записи о клиентах и узлах, а не трафик: десятки килобайт при сотне
// клиентов. Мегабайт с запасом покрывает всё, что человек в состоянии завести руками, и
// защищает от подсунутого файла на гигабайт.
const maxJournal = 1 << 20

// ErrNoGenesis означает, что журнал пуст и сети ещё нет.
var ErrNoGenesis = errors.New("ownerlog: журнала нет, сеть не создана")

// Journal — журнал сети целиком, в памяти.
type Journal struct {
	ops   []*oplog.Op
	state *oplog.State
	// counters — последний счётчик каждого ключа. Нужен, чтобы подписать следующую запись:
	// последовательность ключа не терпит пропусков.
	counters map[oplog.KeyID]uint64
}

// New заводит пустой журнал.
func New() *Journal {
	return &Journal{state: oplog.NewState(), counters: make(map[oplog.KeyID]uint64)}
}

// Read собирает журнал из потока.
//
// Каждая запись проходит те же проверки, что и на узле: подпись, права, место в
// последовательности. Журнал, собранный кем угодно, не даст ничего, кроме ошибки.
func Read(r io.Reader) (*Journal, error) {
	j := New()
	lim := io.LimitReader(r, maxJournal)
	for {
		op, err := oplog.Decode(lim)
		if errors.Is(err, io.EOF) {
			return j, nil
		}
		if err != nil {
			return nil, fmt.Errorf("ownerlog: разбор записи %d: %w", len(j.ops)+1, err)
		}
		if _, err := j.Append(op); err != nil {
			return nil, err
		}
	}
}

// Open читает журнал из файла. Отсутствие файла — пустой журнал, а не ошибка.
func Open(path string) (*Journal, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return New(), nil
		}
		return nil, fmt.Errorf("ownerlog: чтение %s: %w", path, err)
	}
	return Read(bytes.NewReader(raw))
}

// Save записывает журнал в файл.
//
// Через временный файл: обрыв посреди записи оставил бы обрезанный журнал, а в нём лежат ключи
// управления сетью — единственное, что нельзя восстановить ниоткуда.
func (j *Journal) Save(path string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("ownerlog: каталог %s: %w", dir, err)
		}
	}

	var buf bytes.Buffer
	if err := j.Write(&buf); err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("ownerlog: запись %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("ownerlog: замена %s: %w", path, err)
	}
	return nil
}

// Append проверяет запись и добавляет её.
func (j *Journal) Append(op *oplog.Op) (oplog.Effect, error) {
	effect, err := j.state.Apply(op)
	if err != nil {
		return 0, err
	}
	j.ops = append(j.ops, op)
	if op.Counter > j.counters[op.Key] {
		j.counters[op.Key] = op.Counter
	}
	return effect, nil
}

// Write выгружает журнал байт в байт, в том же формате, что и store.Export.
//
// Байт в байт, а не пересборкой: подпись покрывает конкретные байты, и перекодировка по дороге
// сделала бы её непроверяемой.
func (j *Journal) Write(w io.Writer) error {
	for _, op := range j.ops {
		raw, err := op.Bytes()
		if err != nil {
			return err
		}
		if _, err := w.Write(raw); err != nil {
			return fmt.Errorf("ownerlog: запись журнала: %w", err)
		}
	}
	return nil
}

// Bytes отдаёт журнал целиком.
func (j *Journal) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	if err := j.Write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// State — состояние сети по этому журналу.
func (j *Journal) State() *oplog.State { return j.state }

// Len — сколько записей в журнале.
func (j *Journal) Len() int { return len(j.ops) }

// Next — какой счётчик поставить следующей записи этого ключа.
//
// Последовательность каждого ключа идёт без пропусков: узел, увидевший разрыв, запись отложит
// и будет ждать недостающую. Поэтому счётчик берётся из журнала, а не из настроек устройства —
// иначе переустановка приложения сбросила бы его в единицу, и все новые записи оказались бы
// повторами уже применённых.
func (j *Journal) Next(key oplog.KeyID) uint64 { return j.counters[key] + 1 }

// Genesis — отпечаток сети. Нулевой означает, что сети ещё нет.
func (j *Journal) Genesis() oplog.Fingerprint { return j.state.Genesis() }

// bytesReader — короткая запись для bytes.NewReader, чтобы не тащить импорт по всему пакету.
func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
