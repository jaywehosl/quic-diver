// Package oplog описывает журнал операций — единственный способ что-либо изменить в сети.
//
// Устройство изложено в docs/decisions/001-mesh-and-management.md. Коротко: статичная база —
// не таблица, которую кто-то правит, а append-only последовательность подписанных записей.
// Узел проверяет подпись, применяет запись и материализует из неё своё состояние. Подделать
// запись узел не может, поэтому взлом узла не даёт власти над сетью, а бэкап журнала
// самодостаточен и не требует доверия к носителю.
//
// # Что именно подписывается
//
// Подписываются те самые байты, которые хранятся и передаются, — заголовок фиксированного
// формата вместе с телом как есть. Никакой повторной сериализации перед проверкой не
// происходит, поэтому вопрос «каноничного» представления не встаёт вовсе: тело для журнала
// непрозрачно, и его может разбирать только тот, кто понимает вид операции.
//
// Тело кодируется JSON — он расширяем по полям и читаем в дампе, а его неканоничность
// безвредна ровно потому, что подпись покрывает конкретные байты.
package oplog

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Kind — вид операции.
//
// Числовые значения не переиспользуются никогда: узел старой версии обязан уметь сохранить
// запись неизвестного ему вида, не применяя её, и передать соседям в целости. Переназначенный
// номер превратил бы такую запись в тихо неверно понятую.
type Kind uint16

const (
	KindGenesis Kind = 1

	KindAdminAdd    Kind = 10
	KindAdminRevoke Kind = 11

	KindClientAdd    Kind = 20
	KindClientUpdate Kind = 21
	KindClientRevoke Kind = 22

	KindNodeAdd    Kind = 30
	KindNodeUpdate Kind = 31
	KindNodeRevoke Kind = 32

	KindRoutingSet  Kind = 40
	KindSettingsSet Kind = 41
)

func (k Kind) String() string {
	switch k {
	case KindGenesis:
		return "genesis"
	case KindAdminAdd:
		return "admin.add"
	case KindAdminRevoke:
		return "admin.revoke"
	case KindClientAdd:
		return "client.add"
	case KindClientUpdate:
		return "client.update"
	case KindClientRevoke:
		return "client.revoke"
	case KindNodeAdd:
		return "node.add"
	case KindNodeUpdate:
		return "node.update"
	case KindNodeRevoke:
		return "node.revoke"
	case KindRoutingSet:
		return "routing.set"
	case KindSettingsSet:
		return "settings.set"
	default:
		return fmt.Sprintf("kind(%d)", uint16(k))
	}
}

// Known сообщает, понимает ли эта версия смысл операции. Неизвестные записи хранятся и
// пересылаются, но не применяются.
func (k Kind) Known() bool {
	switch k {
	case KindGenesis,
		KindAdminAdd, KindAdminRevoke,
		KindClientAdd, KindClientUpdate, KindClientRevoke,
		KindNodeAdd, KindNodeUpdate, KindNodeRevoke,
		KindRoutingSet, KindSettingsSet:
		return true
	default:
		return false
	}
}

// RequiredScope — минимальные права, при которых операция считается законной.
func (k Kind) RequiredScope() Scope {
	switch k {
	case KindClientAdd, KindClientUpdate, KindClientRevoke:
		return ScopeOperator
	default:
		// Генезис, узлы, права, маршрутизация и настройки сети — только владельцу.
		// Неизвестные виды тоже попадают сюда: если смысл операции непонятен, разрешать
		// её ключу с меньшими правами нельзя.
		return ScopeOwner
	}
}

const (
	magic         = "QDOP"
	formatVersion = 1

	// headerSize: magic(4) + version(1) + kind(2) + keyID(8) + counter(8) + время(8) + длина тела(4).
	headerSize = 4 + 1 + 2 + 8 + 8 + 8 + 4

	// MaxPayloadSize ограничивает тело записи. Журнал ходит по сети и применяется на узлах,
	// поэтому один мегабайт на операцию — с большим запасом, а безразмерная запись была бы
	// готовым способом занять узлу память.
	MaxPayloadSize = 1 << 20

	// EncodedMaxSize — потолок размера всей записи, для читателей потока.
	EncodedMaxSize = headerSize + MaxPayloadSize + ed25519.SignatureSize
)

// signContext отделяет подписи журнала от любых других подписей тем же ключом.
// Без такого разделения подпись, снятая в одном контексте, могла бы быть предъявлена в другом.
const signContext = "qdiver-oplog-v1\x00"

var (
	ErrBadMagic       = errors.New("oplog: не запись журнала")
	ErrBadVersion     = errors.New("oplog: неизвестная версия формата")
	ErrPayloadTooBig  = errors.New("oplog: тело записи больше допустимого")
	ErrBadSignature   = errors.New("oplog: подпись не сходится")
	ErrTruncated      = errors.New("oplog: запись обрывается")
	ErrCounterIsZero  = errors.New("oplog: счётчик операции должен начинаться с единицы")
	ErrUnknownKeyType = errors.New("oplog: публичный ключ неверной длины")
)

// Op — одна запись журнала.
//
// Пара (Key, Counter) уникальна и служит первичным ключом: у каждого ключа своя
// последовательность, поэтому два админа не мешают друг другу и никакой общей нумерации,
// требующей согласования, не нужно.
type Op struct {
	Kind    Kind
	Key     KeyID
	Counter uint64
	Time    time.Time
	Payload []byte
	Sig     []byte
}

// signedBytes собирает то, что покрывается подписью: контекст, заголовок и тело.
func (o *Op) signedBytes() []byte {
	buf := make([]byte, 0, len(signContext)+headerSize+len(o.Payload))
	buf = append(buf, signContext...)
	buf = append(buf, magic...)
	buf = append(buf, formatVersion)
	buf = binary.BigEndian.AppendUint16(buf, uint16(o.Kind))
	buf = append(buf, o.Key[:]...)
	buf = binary.BigEndian.AppendUint64(buf, o.Counter)
	buf = binary.BigEndian.AppendUint64(buf, uint64(o.Time.UnixMilli()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(o.Payload)))
	buf = append(buf, o.Payload...)
	return buf
}

// Sign заполняет Key и Sig, подписывая операцию.
func (o *Op) Sign(s Signer) error {
	if o.Counter == 0 {
		return ErrCounterIsZero
	}
	if len(o.Payload) > MaxPayloadSize {
		return ErrPayloadTooBig
	}
	pub := s.Public()
	if len(pub) != ed25519.PublicKeySize {
		return ErrUnknownKeyType
	}
	o.Key = KeyIDOf(pub)
	if o.Time.IsZero() {
		return errors.New("oplog: время операции не задано")
	}
	// Время храним с точностью до миллисекунды — именно оно попадёт под подпись,
	// поэтому и в структуре оставляем усечённое, иначе Verify не сойдётся с Sign.
	o.Time = time.UnixMilli(o.Time.UnixMilli()).UTC()

	sig, err := s.Sign(o.signedBytes())
	if err != nil {
		return fmt.Errorf("oplog: подпись операции: %w", err)
	}
	o.Sig = sig
	return nil
}

// Verify проверяет подпись переданным публичным ключом и заодно то, что ключ действительно
// тот, чей идентификатор указан в записи.
func (o *Op) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrUnknownKeyType
	}
	if KeyIDOf(pub) != o.Key {
		return fmt.Errorf("oplog: ключ %s не соответствует записи от %s", KeyIDOf(pub), o.Key)
	}
	if len(o.Sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !ed25519.Verify(pub, o.signedBytes(), o.Sig) {
		return ErrBadSignature
	}
	return nil
}

// Encode пишет запись в поток.
func (o *Op) Encode(w io.Writer) error {
	if len(o.Sig) != ed25519.SignatureSize {
		return fmt.Errorf("oplog: запись не подписана")
	}
	if len(o.Payload) > MaxPayloadSize {
		return ErrPayloadTooBig
	}
	body := o.signedBytes()[len(signContext):] // заголовок и тело без контекста подписи
	if _, err := w.Write(body); err != nil {
		return err
	}
	_, err := w.Write(o.Sig)
	return err
}

// Bytes отдаёт запись целиком одним куском — так она и хранится в базе.
func (o *Op) Bytes() ([]byte, error) {
	if len(o.Sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("oplog: запись не подписана")
	}
	body := o.signedBytes()[len(signContext):]
	out := make([]byte, 0, len(body)+len(o.Sig))
	out = append(out, body...)
	out = append(out, o.Sig...)
	return out, nil
}

// Decode читает одну запись из потока.
//
// Подпись здесь не проверяется: у читателя может не быть публичного ключа под рукой.
// Проверка — отдельный шаг, и пропустить его нельзя: непроверенная запись не должна
// доходить до применения.
func Decode(r io.Reader) (*Op, error) {
	head := make([]byte, headerSize)
	if _, err := io.ReadFull(r, head); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrTruncated
		}
		return nil, err
	}
	if string(head[:4]) != magic {
		return nil, ErrBadMagic
	}
	if head[4] != formatVersion {
		return nil, fmt.Errorf("%w: %d", ErrBadVersion, head[4])
	}

	o := &Op{
		Kind:    Kind(binary.BigEndian.Uint16(head[5:7])),
		Counter: binary.BigEndian.Uint64(head[15:23]),
		Time:    time.UnixMilli(int64(binary.BigEndian.Uint64(head[23:31]))).UTC(),
	}
	copy(o.Key[:], head[7:15])

	length := binary.BigEndian.Uint32(head[31:35])
	if length > MaxPayloadSize {
		return nil, ErrPayloadTooBig
	}
	if length > 0 {
		o.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, o.Payload); err != nil {
			return nil, ErrTruncated
		}
	}

	o.Sig = make([]byte, ed25519.SignatureSize)
	if _, err := io.ReadFull(r, o.Sig); err != nil {
		return nil, ErrTruncated
	}
	return o, nil
}
