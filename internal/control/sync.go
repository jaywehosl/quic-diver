package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/store"
)

// Offer — где собеседник находится: последний применённый счётчик по каждому ключу.
//
// Этого достаточно, чтобы понять, чего ему недостаёт: у каждого админского ключа своя
// последовательность без пропусков, поэтому одно число на ключ описывает всё, что у него есть.
type Offer struct {
	Counters map[string]uint64 `json:"counters"`
}

// SyncResult — что дал обмен.
type SyncResult struct {
	// Sent — сколько записей отдали.
	Sent int
	// Received — сколько приняли и применили.
	Received int
}

// Sync обменивается журналом с собеседником.
//
// Обмен симметричный: обе стороны говорят, где находятся, и каждая отдаёт недостающее.
// Поэтому одна и та же функция годится обоим — кто первым начал, значения не имеет.
//
// Соединением Sync не владеет и не закрывает его. При ошибке рвать связь обязан вызывающий:
// сторона, отвергнувшая записи, перестаёт читать, и вторая упрётся в запись, ожидая места в
// окне. Без разрыва такая пара зависнет.
//
// Чтение и запись идут одновременно, в разных горутинах, и это не украшение. Обе стороны
// начинают с отправки: если писать, не читая, обмен встаёт, как только написанное перестанет
// помещаться в окно — у QUIC оно конечное, у net.Pipe его нет вовсе. Симметричный протокол
// поверх однопоточного «сначала пишу, потом читаю» — это дедлок, ждущий достаточно длинного
// журнала.
func Sync(rw io.ReadWriter, st *store.Store) (SyncResult, error) {
	type half struct {
		sent, received int
		err            error
	}

	// Писать теперь могут обе горутины: отказ уходит из читающей, обычные кадры — из пишущей.
	// Мьютекс делает кадр неделимым, а больше ничего и не нужно: WriteFrame пишет ровно один
	// раз, поэтому два кадра не перемешаются байтами.
	w := &lockedWriter{w: rw}

	theirOffer := make(chan map[oplog.KeyID]uint64, 1)
	reading := make(chan half, 1)
	writing := make(chan half, 1)

	go func() {
		counters, err := readOffer(rw)
		if err != nil {
			close(theirOffer)
			reading <- half{err: err}
			return
		}
		theirOffer <- counters

		received, err := readRecords(rw, st)
		if err != nil && !errors.Is(err, ErrRejected) {
			// Называем причину, пока связь ещё жива, — но не ждём, пока она уйдёт.
			//
			// Ждать нельзя: отказ бывает обоюдным (две чужие друг другу сети), и тогда обе
			// стороны пишут, обе перестали читать, и обе стоят навсегда. Отдельная горутина
			// разблокируется разрывом связи, который сделает вызывающий, — а он его сделает,
			// потому что Sync к тому моменту уже вернул ошибку.
			//
			// Свой отказ в ответ на чужой не шлётся: собеседник уже сказал, что не читает.
			go func() { _ = writeReject(w, err) }()
		}
		reading <- half{received: received, err: err}
	}()

	go func() {
		if err := writeOffer(w, st.Counters()); err != nil {
			writing <- half{err: err}
			return
		}
		counters, ok := <-theirOffer
		if !ok {
			// Читающая сторона уже провалилась; настоящую ошибку вернёт она.
			writing <- half{}
			return
		}
		missing, err := st.Since(counters)
		if err != nil {
			writing <- half{err: err}
			return
		}
		if err := writeRecords(w, missing); err != nil {
			writing <- half{err: err}
			return
		}
		writing <- half{sent: len(missing)}
	}()

	// Возвращаемся по первой же беде, не дожидаясь второй половины.
	//
	// Иначе выходит вот что: собеседник отверг наши записи и перестал читать, мы упёрлись в
	// запись — и ждём его вечно, пока он ждёт нас. Разорвать связь может только вызывающий,
	// но он не станет этого делать, пока Sync не вернулся. Оставшаяся горутина разблокируется
	// как раз разрывом.
	var res SyncResult
	var wrote, read half
	var gotW, gotR bool
	for !gotW || !gotR {
		select {
		case wrote = <-writing:
			gotW = true
			res.Sent = wrote.sent
			if wrote.err != nil {
				return res, wrote.err
			}
		case read = <-reading:
			gotR = true
			res.Received = read.received
			if read.err != nil {
				return res, read.err
			}
		}
	}
	return res, nil
}

// lockedWriter сериализует запись кадров из нескольких горутин.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// maxReason ограничивает длину причины отказа.
//
// Причина идёт человеку на экран, а не машине в разбор. Ошибка журнала укладывается в строку;
// всё, что длиннее, — либо чужая фантазия, либо цепочка обёрток, из которой полезен только хвост.
const maxReason = 512

// ErrRejected — собеседник отверг наши записи и назвал причину.
var ErrRejected = errors.New("control: собеседник отверг записи")

func writeReject(w io.Writer, cause error) error {
	reason := cause.Error()
	if len(reason) > maxReason {
		reason = reason[:maxReason]
	}
	return WriteFrame(w, KindReject, []byte(reason))
}

// rejected превращает пришедший отказ в ошибку с причиной собеседника.
//
// Текст пришёл по сети, то есть от стороны, которой мы верим ровно настолько, насколько
// опознали. Печатается он через %q — чтобы перевод строки или управляющий символ в чужой
// причине не подделал вывод, будто это наша собственная строка журнала.
func rejected(f *Frame) error {
	reason := string(f.Payload)
	if len(reason) > maxReason {
		reason = reason[:maxReason]
	}
	if reason == "" {
		return ErrRejected
	}
	return fmt.Errorf("%w: %q", ErrRejected, reason)
}

func writeOffer(w io.Writer, counters map[oplog.KeyID]uint64) error {
	o := Offer{Counters: make(map[string]uint64, len(counters))}
	for id, n := range counters {
		o.Counters[id.String()] = n
	}
	body, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("control: кодирование предложения: %w", err)
	}
	return WriteFrame(w, KindSyncOffer, body)
}

func readOffer(r io.Reader) (map[oplog.KeyID]uint64, error) {
	f, err := ReadFrame(r)
	if err != nil {
		return nil, err
	}
	if f.Kind == KindReject {
		return nil, rejected(f)
	}
	if f.Kind != KindSyncOffer {
		return nil, fmt.Errorf("control: ждали %s, пришло %s", KindSyncOffer, f.Kind)
	}

	var o Offer
	if err := json.Unmarshal(f.Payload, &o); err != nil {
		return nil, fmt.Errorf("control: разбор предложения: %w", err)
	}
	out := make(map[oplog.KeyID]uint64, len(o.Counters))
	for s, n := range o.Counters {
		id, err := oplog.ParseKeyID(s)
		if err != nil {
			// Мусор в чужом предложении не повод рвать обмен: непонятный ключ просто
			// означает, что мы ничего про него не знаем и ничего по нему не отдадим.
			continue
		}
		out[id] = n
	}
	return out, nil
}

// writeRecords отдаёт записи одним кадром.
//
// Записи едут байт в байт, как лежат в журнале: подпись покрывает именно эти байты, и
// пересборка по дороге сделала бы её непроверяемой.
func writeRecords(w io.Writer, ops []*oplog.Op) error {
	var buf bytes.Buffer
	for _, op := range ops {
		raw, err := op.Bytes()
		if err != nil {
			return err
		}
		if buf.Len()+len(raw) > MaxFrame {
			// Кадр заполнен. Отдаём что набралось: остальное собеседник дозапросит
			// следующим обменом, потому что его счётчики сдвинутся ровно на отданное.
			break
		}
		buf.Write(raw)
	}
	if err := WriteFrame(w, KindSyncRecords, buf.Bytes()); err != nil {
		return err
	}
	return WriteFrame(w, KindSyncDone, nil)
}

func readRecords(r io.Reader, st *store.Store) (int, error) {
	f, err := ReadFrame(r)
	if err != nil {
		return 0, err
	}
	if f.Kind == KindReject {
		// Отказ на наши записи, а не на его. Обмен симметричный, и отвергнуть могли нас.
		return 0, rejected(f)
	}
	if f.Kind != KindSyncRecords {
		return 0, fmt.Errorf("control: ждали %s, пришло %s", KindSyncRecords, f.Kind)
	}

	// Вливание идемпотентно и проверяет каждую запись: подпись, права, место в
	// последовательности. Собеседник опознан, но это не повод верить его записям.
	n, err := st.Import(bytes.NewReader(f.Payload))
	if err != nil {
		return n, fmt.Errorf("control: приём записей: %w", err)
	}

	done, err := ReadFrame(r)
	if err != nil {
		return n, err
	}
	if done.Kind == KindReject {
		return n, rejected(done)
	}
	if done.Kind != KindSyncDone {
		return n, fmt.Errorf("control: ждали %s, пришло %s", KindSyncDone, done.Kind)
	}
	return n, nil
}
