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
	"time"

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
	// expect — отпечаток сети, к которой мы принадлежим. Нулевой означает «любая»: так журнал
	// создаётся, когда сеть в нём и рождается.
	expect oplog.Fingerprint
	// latest — время самой поздней записи. Нужно, чтобы следующая была строго позже (tick).
	latest time.Time
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

// Expect задаёт отпечаток сети, к которой журнал принадлежит.
//
// Нужно ровно в одном случае — когда журнал пуст и его собираются наполнить по сети: владелец
// вставил свою ссылку на чистом устройстве и забирает журнал у узла. Проверить подпись генезиса
// нечем (ключи владельцев объявляет он сам), поэтому единственное, что отличает свою сеть от
// чужой, — отпечаток из ссылки.
//
// Тот же довод, по которому узел не принимает чужой журнал первым заливом (решение 007 §3.3).
func (j *Journal) Expect(fp oplog.Fingerprint) { j.expect = fp }

// Append проверяет запись и добавляет её.
func (j *Journal) Append(op *oplog.Op) (oplog.Effect, error) {
	// Генезис — единственная запись, для которой подписи недостаточно: он сам объявляет ключи
	// владельцев, и любой правильно собранный чужой генезис пройдёт проверку с блеском.
	if op.Kind == oplog.KindGenesis && !j.expect.IsZero() {
		fp, err := oplog.FingerprintOf(op)
		if err != nil {
			return 0, err
		}
		if fp != j.expect {
			return 0, fmt.Errorf("ownerlog: журнал от другой сети: у него %s, ждали %s", fp, j.expect)
		}
	}

	effect, err := j.state.Apply(op)
	if err != nil {
		return 0, err
	}
	j.ops = append(j.ops, op)
	if op.Counter > j.counters[op.Key] {
		j.counters[op.Key] = op.Counter
	}
	if op.Time.After(j.latest) {
		j.latest = op.Time
	}
	return effect, nil
}

// tick выдаёт время следующей записи — строго позже предыдущей.
//
// Часы здесь не роскошь, а способ разрешать конфликты: две правки одного объекта сравниваются
// по паре (время, ключ), и та, что раньше, проигрывает. Записи, попавшие в одну миллисекунду,
// оказываются равными — и вторая молча отбрасывается как «не новее».
//
// Само по себе это редкость, но не для нас: часы Windows тикают раз в 10–15 мс, а человек
// нажимает кнопки быстрее. Приостановить клиента и тут же вернуть — и возврат пропадает,
// причём без единой ошибки: журнал считает, что запись законна, просто устарела.
//
// Поэтому время берётся не у часов напрямую, а сдвигается вперёд, если часы не успели.
// Расхождение с настоящим временем на миллисекунды безвредно: сеть сверяет порядок записей, а
// не показания часов.
//
// Округление до миллисекунды здесь обязательно, а не для красоты: запись хранит время именно в
// миллисекундах (oplog.NewOp усекает его при подписи). Сравнивать неокруглённые часы с временем
// уже записанной записи бессмысленно — разница в доли миллисекунды исчезнет при подписи, и обе
// записи окажутся одновременными.
func (j *Journal) tick() time.Time {
	now := time.Now().UTC().Truncate(time.Millisecond)
	if !now.After(j.latest) {
		now = j.latest.Add(time.Millisecond)
	}
	return now
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

// Обмен журналами с узлом (control.Log).
//
// Тот же обмен, каким сверяются узлы между собой: обе стороны говорят, где находятся, и
// досылают недостающее. Владельцу он нужен по двум поводам сразу — донести свою правку до сети
// и забрать чужие: узлы правит не только это устройство, и запасная ссылка на другом телефоне
// подписывает записи своим ключом.

// Counters — последний счётчик каждого ключа. С этого начинается обмен.
func (j *Journal) Counters() map[oplog.KeyID]uint64 {
	out := make(map[oplog.KeyID]uint64, len(j.counters))
	for id, n := range j.counters {
		out[id] = n
	}
	return out
}

// Since отдаёт записи, которых у собеседника нет.
//
// Перебором по всему журналу, без индексов: записей десятки, и заводить ради них ту же
// машинерию, что у узла, незачем.
func (j *Journal) Since(have map[oplog.KeyID]uint64) ([]*oplog.Op, error) {
	var out []*oplog.Op
	for _, op := range j.ops {
		if op.Counter > have[op.Key] {
			out = append(out, op)
		}
	}
	return out, nil
}

// Import вливает присланное собеседником.
//
// Каждая запись проходит те же проверки, что и на узле: подпись, права, место в
// последовательности. Уже применённое пропускается молча — сосед присылает и то, что мы давно
// знаем, и падать на этом было бы странно.
func (j *Journal) Import(r io.Reader) (int, error) {
	added := 0
	lim := io.LimitReader(r, maxJournal)
	for {
		op, err := oplog.Decode(lim)
		if errors.Is(err, io.EOF) {
			return added, nil
		}
		if err != nil {
			return added, fmt.Errorf("ownerlog: разбор присланной записи: %w", err)
		}

		switch _, err := j.Append(op); {
		case err == nil:
			added++
		case errors.Is(err, oplog.ErrReplay), errors.Is(err, oplog.ErrDoubleGenesis):
			// Уже применяли. Для генезиса это ещё и проверка сети: чужой отличался бы
			// отпечатком, и запись не совпала бы с нашей.
			if op.Kind == oplog.KindGenesis {
				fp, ferr := oplog.FingerprintOf(op)
				if ferr != nil {
					return added, ferr
				}
				if fp != j.Genesis() {
					return added, fmt.Errorf("ownerlog: журнал от другой сети: у них %s, у нас %s",
						fp, j.Genesis())
				}
			}
		default:
			return added, err
		}
	}
}

// bytesReader — короткая запись для bytes.NewReader, чтобы не тащить импорт по всему пакету.
func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
