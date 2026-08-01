// Package control — язык управляющего канала.
//
// Канал уже установлен и обе стороны опознаны (см. internal/hello), поэтому здесь нет ни
// аутентификации, ни шифрования: и то и другое ниже. Остаётся кадрирование и несколько
// видов сообщений.
//
// Формат намеренно скучный: тип, длина, тело. Тело либо JSON, либо сырые записи журнала —
// их пересылают как есть, потому что подпись покрывает именно эти байты, и любая
// перекодировка по дороге сделала бы её непроверяемой.
package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Kind — вид сообщения.
type Kind uint8

const (
	// KindSyncOffer — «вот где я нахожусь»: счётчик по каждому известному ключу.
	KindSyncOffer Kind = 1
	// KindSyncRecords — записи журнала, которых у собеседника нет.
	KindSyncRecords Kind = 2
	// KindSyncDone — больше отдавать нечего.
	KindSyncDone Kind = 3
	// KindPing — проверка живости, она же измерение времени отклика.
	KindPing Kind = 4
	// KindPong — ответ на проверку.
	KindPong Kind = 5
	// KindSnapshot — выжимка из журнала для клиента: правила, параметры сети, узлы.
	// Едет от узла к клиенту без запроса — при подключении и на каждое изменение журнала.
	KindSnapshot Kind = 6
	// KindUsage — динамическая база: счётчики трафика и живые сессии. Ходит между узлами
	// в обе стороны.
	KindUsage Kind = 7
	// KindReject — «твои записи не приняты, вот почему». Тело — текст причины.
	//
	// Нужен затем, что отказ по правам иначе выглядит обрывом связи. Администратор, чей ключ
	// не тянет на операцию, увидел бы «узел отвалился» и полез искать сеть — вместо того
	// чтобы прочитать, что операция требует владельца, а у него оператор.
	KindReject Kind = 8
)

func (k Kind) String() string {
	switch k {
	case KindSyncOffer:
		return "sync-offer"
	case KindSyncRecords:
		return "sync-records"
	case KindSyncDone:
		return "sync-done"
	case KindPing:
		return "ping"
	case KindPong:
		return "pong"
	case KindSnapshot:
		return "snapshot"
	case KindUsage:
		return "usage"
	case KindReject:
		return "reject"
	default:
		return fmt.Sprintf("kind(%d)", uint8(k))
	}
}

// MaxFrame ограничивает кадр.
//
// Управляющий канал обслуживает опознанного собеседника, но опознанный не значит исправный:
// сосед с испорченной памятью или просто чужой версии не должен уметь заставить нас выделить
// произвольный кусок памяти одним числом в заголовке.
const MaxFrame = 4 << 20

const headerSize = 1 + 4

var (
	ErrFrameTooBig = errors.New("control: кадр больше допустимого")
	ErrTruncated   = errors.New("control: кадр обрывается")
)

// Frame — одно сообщение.
type Frame struct {
	Kind    Kind
	Payload []byte
}

// WriteFrame отправляет сообщение.
func WriteFrame(w io.Writer, kind Kind, payload []byte) error {
	if len(payload) > MaxFrame {
		return ErrFrameTooBig
	}
	head := make([]byte, headerSize, headerSize+len(payload))
	head[0] = byte(kind)
	binary.BigEndian.PutUint32(head[1:], uint32(len(payload)))
	head = append(head, payload...)
	if _, err := w.Write(head); err != nil {
		return fmt.Errorf("control: отправка %s: %w", kind, err)
	}
	return nil
}

// ReadFrame принимает сообщение.
func ReadFrame(r io.Reader) (*Frame, error) {
	head := make([]byte, headerSize)
	if _, err := io.ReadFull(r, head); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrTruncated
		}
		return nil, err
	}
	length := binary.BigEndian.Uint32(head[1:])
	if length > MaxFrame {
		return nil, fmt.Errorf("%w: заявлено %d байт", ErrFrameTooBig, length)
	}

	f := &Frame{Kind: Kind(head[0])}
	if length > 0 {
		f.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, ErrTruncated
		}
	}
	return f, nil
}
