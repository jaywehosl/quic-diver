// Package dnsproxy отвечает на DNS-запросы, пришедшие из туннеля.
//
// Это то место, где у потока появляется имя. Всё остальное — правила по доменам, блокировки,
// выход в IPv6 с машины без IPv6 — держится на нём.
//
// # Что происходит с запросом
//
//	A      → подменный адрес из пула, имя запоминается
//	AAAA   → пустой успешный ответ
//	прочее → к настоящему резолверу через узел
//
// Пустой ответ на AAAA — не небрежность. Приложение, не получив адреса v6, идёт по v4 на
// подменный адрес; дальше имя разрешает узел и выходит по тому семейству, которое есть у
// самого имени. Так домен, живущий только в IPv6, открывается с машины, где IPv6 нет вовсе.
// Отдавать здесь подменный v6 значило бы делать ту же работу дважды.
//
// # Про честность
//
// Подменный ответ — это подделка DNS, и никакой DNSSEC на клиенте после неё не проверить.
// Отклонение сознательное и оговорено в решении 000 §5: без него правила по доменам под
// полным туннелем не работают вовсе. Настоящую проверку подписи делает резолвер узла, а не
// клиент.
package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"time"

	"github.com/jaywehosl/quic-diver/internal/fakeip"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	// fakeTTL — время жизни подменного ответа.
	//
	// Короткое намеренно: аренда в пуле живёт куда дольше, поэтому потерять соответствие
	// нельзя, а вот перезапросить имя после смены правил приложение сможет быстро.
	fakeTTL = 60

	// maxMessage — потолок размера ответа настоящего резолвера.
	maxMessage = 64 << 10

	// upstreamTimeout — сколько ждём настоящий резолвер.
	upstreamTimeout = 8 * time.Second
)

// Opener открывает поток до адреса через сеть.
type Opener interface {
	Open(ctx context.Context, target string) (io.ReadWriteCloser, error)
}

// Decider решает, заблокировано ли имя.
type Decider interface {
	// Blocked сообщает, что имя запрещено правилами.
	Blocked(name string) bool
}

// Server отвечает на запросы.
type Server struct {
	// Pool раздаёт подменные адреса.
	Pool *fakeip.Pool
	// Upstream — настоящий резолвер, адрес вида "1.1.1.1:53".
	Upstream string
	// Open — чем открывать поток до резолвера.
	Open Opener
	// Rules — чем проверять запрет. Пустой означает, что ничего не запрещено.
	Rules Decider
	// KeepDNS перехватывает шифрованный DNS: имена известных резолверов DoH получают отказ,
	// и браузер откатывается на системный резолвер — то есть на нас (см. doh.go).
	//
	// Иначе браузер разрешает имена сам, минуя туннель, и правила по доменам перестают
	// работать целиком — молча, без единой строки в журнале.
	KeepDNS bool
	// Log — куда писать.
	Log *slog.Logger
}

// Handle отвечает на один запрос.
func (s *Server) Handle(ctx context.Context, query []byte) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, fmt.Errorf("dnsproxy: разбор запроса: %w", err)
	}

	question, err := parser.Question()
	if err != nil {
		// Запрос без вопроса — либо мусор, либо чужая затея. Отвечаем отказом формата.
		return s.fail(header, dnsmessage.Question{}, dnsmessage.RCodeFormatError)
	}

	name := trimDot(question.Name.String())

	switch {
	case s.Rules != nil && s.Rules.Blocked(name):
		// Мгновенный отказ вместо молчания: приложение узнаёт правду сразу, а не после
		// таймаута. Это и есть та самая мгновенная блокировка из ТЗ.
		s.log().Debug("имя заблокировано", "name", name)
		return s.fail(header, question, dnsmessage.RCodeNameError)

	case s.KeepDNS && blocksDoH(name):
		// Отказ имени резолвера DoH — обычный NXDOMAIN, а не подмена ответа: мы не выдаём
		// себя за чужой сервер и ничего не расшифровываем. Браузер, не сумевший найти свой
		// резолвер, возвращается к системному.
		s.log().Debug("шифрованный DNS отклонён", "name", name)
		return s.fail(header, question, dnsmessage.RCodeNameError)

	case question.Type == dnsmessage.TypeA && question.Class == dnsmessage.ClassINET:
		return s.answerA(header, question, name)

	case question.Type == dnsmessage.TypeAAAA && question.Class == dnsmessage.ClassINET:
		// Пустой успешный ответ: пусть идёт по v4 на подменный адрес.
		return s.empty(header, question)

	default:
		return s.forward(ctx, query, header, question)
	}
}

// answerA выдаёт подменный адрес.
func (s *Server) answerA(header dnsmessage.Header, q dnsmessage.Question, name string) ([]byte, error) {
	addr, err := s.Pool.Assign(name)
	if err != nil {
		s.log().Warn("подменный адрес не выдан", "name", name, "err", err)
		return s.fail(header, q, dnsmessage.RCodeServerFailure)
	}

	builder := s.reply(header, q)
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	err = builder.AResource(
		dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: fakeTTL},
		dnsmessage.AResource{A: addr.As4()},
	)
	if err != nil {
		return nil, err
	}
	return builder.Finish()
}

// empty отвечает успехом без записей.
func (s *Server) empty(header dnsmessage.Header, q dnsmessage.Question) ([]byte, error) {
	builder := s.reply(header, q)
	return builder.Finish()
}

// fail отвечает кодом ошибки.
func (s *Server) fail(header dnsmessage.Header, q dnsmessage.Question, code dnsmessage.RCode) ([]byte, error) {
	reply := dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		OpCode:             header.OpCode,
		Authoritative:      true,
		RecursionDesired:   header.RecursionDesired,
		RecursionAvailable: true,
		RCode:              code,
	}
	builder := dnsmessage.NewBuilder(nil, reply)
	builder.EnableCompression()
	if q.Name.Length > 0 {
		if err := builder.StartQuestions(); err != nil {
			return nil, err
		}
		if err := builder.Question(q); err != nil {
			return nil, err
		}
	}
	return builder.Finish()
}

func (s *Server) reply(header dnsmessage.Header, q dnsmessage.Question) *dnsmessage.Builder {
	replyHeader := dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		OpCode:             header.OpCode,
		Authoritative:      true,
		RecursionDesired:   header.RecursionDesired,
		RecursionAvailable: true,
	}
	builder := dnsmessage.NewBuilder(nil, replyHeader)
	builder.EnableCompression()
	_ = builder.StartQuestions()
	_ = builder.Question(q)
	return &builder
}

// forward отправляет запрос настоящему резолверу через сеть.
//
// По TCP (RFC 7766), а не по UDP: поток через узел — это TCP, и городить проксирование
// датаграмм ради DNS незачем. Заодно снимается вопрос обрезанных ответов.
func (s *Server) forward(
	ctx context.Context,
	query []byte,
	header dnsmessage.Header,
	q dnsmessage.Question,
) ([]byte, error) {
	if s.Open == nil || s.Upstream == "" {
		return s.fail(header, q, dnsmessage.RCodeServerFailure)
	}

	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()

	stream, err := s.Open.Open(ctx, s.Upstream)
	if err != nil {
		s.log().Debug("резолвер недоступен", "upstream", s.Upstream, "err", err)
		return s.fail(header, q, dnsmessage.RCodeServerFailure)
	}
	defer stream.Close()

	// Длина сообщения двумя байтами впереди — так устроен DNS поверх TCP.
	framed := make([]byte, 2+len(query))
	framed[0] = byte(len(query) >> 8)
	framed[1] = byte(len(query))
	copy(framed[2:], query)

	if _, err := stream.Write(framed); err != nil {
		return s.fail(header, q, dnsmessage.RCodeServerFailure)
	}

	var length [2]byte
	if _, err := io.ReadFull(stream, length[:]); err != nil {
		return s.fail(header, q, dnsmessage.RCodeServerFailure)
	}
	size := int(length[0])<<8 | int(length[1])
	if size == 0 || size > maxMessage {
		return s.fail(header, q, dnsmessage.RCodeServerFailure)
	}

	answer := make([]byte, size)
	if _, err := io.ReadFull(stream, answer); err != nil {
		return s.fail(header, q, dnsmessage.RCodeServerFailure)
	}
	return answer, nil
}

// ResolveA узнаёт настоящие адреса имени.
//
// Нужно ровно для правил по подсетям: приложению мы выдали подменный адрес, а условию
// `geoip:ru` требуется настоящий. Спрашиваем тем же путём и того же резолвера, что и обычные
// запросы, — то есть через узел, а не мимо туннеля.
//
// Ответ не кешируется здесь: он ложится рядом с подменным адресом и живёт ровно столько же
// (см. fakeip.Pool.SetReal). Второго кеша с собственным сроком жизни проект не заводит.
func (s *Server) ResolveA(ctx context.Context, name string) ([]netip.Addr, error) {
	if s.Open == nil || s.Upstream == "" {
		return nil, errors.New("dnsproxy: резолвер не задан")
	}

	dnsName, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, fmt.Errorf("dnsproxy: имя %q: %w", name, err)
	}
	q := dnsmessage.Question{Name: dnsName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}

	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: true})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(q); err != nil {
		return nil, err
	}
	query, err := builder.Finish()
	if err != nil {
		return nil, err
	}

	raw, err := s.forward(ctx, query, dnsmessage.Header{RecursionDesired: true}, q)
	if err != nil {
		return nil, err
	}

	var parser dnsmessage.Parser
	if _, err := parser.Start(raw); err != nil {
		return nil, err
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, err
	}

	var out []netip.Addr
	for {
		h, err := parser.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return out, nil
		}
		if h.Type != dnsmessage.TypeA {
			if err := parser.SkipAnswer(); err != nil {
				return out, nil
			}
			continue
		}
		res, err := parser.AResource()
		if err != nil {
			return out, nil
		}
		out = append(out, netip.AddrFrom4(res.A))
	}
	return out, nil
}

// ServePacket обслуживает одно пакетное соединение из туннеля.
func (s *Server) ServePacket(ctx context.Context, conn io.ReadWriter) error {
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}

		answer, err := s.Handle(ctx, buf[:n])
		if err != nil {
			s.log().Debug("запрос не обработан", "err", err)
			continue
		}
		if _, err := conn.Write(answer); err != nil {
			return err
		}
	}
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func trimDot(name string) string {
	if len(name) > 0 && name[len(name)-1] == '.' {
		return name[:len(name)-1]
	}
	return name
}

// IsDNS сообщает, что соединение идёт к службе имён.
func IsDNS(target netip.AddrPort) bool { return target.Port() == 53 }
