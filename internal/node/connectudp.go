package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// Проксирование UDP по RFC 9298.
//
// Метод — расширенный CONNECT (RFC 9220) со значением `connect-udp`, и здесь, в отличие от
// управляющего канала, изобретать ничего не пришлось: значение зарегистрировано в реестре
// HTTP Upgrade Token, шаблон пути описан в самом RFC, датаграммы едут по RFC 9297. Снаружи
// это обычный запрос HTTP/3.
//
// # Почему датаграммы, а не поток
//
// UDP теряет пакеты по своей природе, и приложения к этому готовы. Уложить его в надёжный
// поток значило бы заставить свежие пакеты ждать переотправки старых: голос и игры от этого
// страдают сильнее, чем от самой потери. Заодно так сохраняются границы сообщений — для UDP
// они и есть содержание.

const (
	// udpProtocol — значение :protocol из реестра HTTP Upgrade Token (RFC 9298 §3).
	udpProtocol = "connect-udp"

	// udpPrefix — начало шаблона пути из RFC 9298 §3.
	udpPrefix = "/.well-known/masque/udp/"

	// contextIDDatagram — идентификатор контекста полезной нагрузки (RFC 9298 §4).
	// Нулевой контекст означает «дальше идёт сама датаграмма».
	contextIDDatagram = 0

	// udpIdleTimeout — сколько внешний сокет живёт без пакетов.
	//
	// У UDP нет закрытия соединения: ушедший клиент не сообщает об этом никак, и без срока
	// сокет остался бы навсегда. Минута отсчитывается от последнего пакета в любую сторону.
	udpIdleTimeout = time.Minute

	// maxDatagram ограничивает пакет, читаемый из внешнего сокета.
	maxDatagram = 1500
)

// errNotUDPPath означает, что путь не по шаблону RFC 9298.
var errNotUDPPath = errors.New("путь не по шаблону connect-udp")

// udpPath собирает путь запроса для адреса.
func udpPath(target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("node: адрес %q: %w", target, err)
	}
	if host == "" || port == "" {
		return "", fmt.Errorf("node: неполный адрес %q", target)
	}
	// Части экранируются: имя и порт подставляются в шаблон как отдельные сегменты пути, и
	// двоеточия адреса IPv6 сегментом быть не должны.
	return udpPrefix + url.PathEscape(host) + "/" + url.PathEscape(port) + "/", nil
}

// parseUDPPath разбирает путь запроса обратно в адрес.
//
// Берётся именно экранированный путь: разобранный уже потерял бы разницу между разделителем
// сегментов и косой чертой внутри имени.
func parseUDPPath(u *url.URL) (string, error) {
	path := u.EscapedPath()
	if !strings.HasPrefix(path, udpPrefix) {
		return "", errNotUDPPath
	}
	parts := strings.Split(strings.TrimPrefix(path, udpPrefix), "/")
	// Шаблон кончается косой чертой, поэтому частей ровно три, и последняя пуста.
	if len(parts) != 3 || parts[2] != "" {
		return "", errNotUDPPath
	}

	host, err := url.PathUnescape(parts[0])
	if err != nil || host == "" {
		return "", errNotUDPPath
	}
	port, err := url.PathUnescape(parts[1])
	if err != nil {
		return "", errNotUDPPath
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", errNotUDPPath
	}
	return net.JoinHostPort(host, port), nil
}

// serveConnectUDP выпускает наружу датаграммы.
//
// Разбор тот же, что у обычного CONNECT: опознание берётся из таблицы сессий, неопознанный
// получает страницу заглушки. Отличие одно — наружу открывается пакетный сокет, а не поток.
func (n *Node) serveConnectUDP(w http.ResponseWriter, r *http.Request) {
	binding, err := bindingOf(r)
	if err != nil {
		n.reject(w, r, "нет привязки к сессии")
		return
	}
	peer, ok := n.sessions.lookup(binding)
	if !ok {
		n.reject(w, r, "соединение не проходило приветствия")
		return
	}
	n.markActive(binding, peer)

	target, err := parseUDPPath(r.URL)
	if err != nil {
		n.reject(w, r, "негодный путь: "+err.Error())
		return
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		n.reject(w, r, "поток не захватывается")
		return
	}

	// Метка маршрута та же, что у потоков: клиент просит выпустить не здесь, а через
	// выходной узел. Без неё датаграммы уходили бы наружу на входном узле, и приложение,
	// говорящее по QUIC, оказалось бы совсем не там, где остальной его трафик.
	viaExit := r.Header.Get(ExitHeader) == ExitYes && n.cfg.Exits != nil
	client := clientOf(peer, r)

	remote, via, err := n.openPackets(r.Context(), target, viaExit, client)
	if err != nil {
		n.log.Debug("наружу не вышло", "peer", peer.ID, "target", target, "err", err)
		n.cfg.Decoy.Error(w, r, http.StatusBadGateway)
		return
	}
	defer remote.Close()

	w.Header().Set(ExitVia, via)
	w.WriteHeader(http.StatusOK)

	stream := streamer.HTTPStream()
	local := newPacketStream(r.Context(), stream, stream, stream,
		n.log.With("peer", peer.ID, "target", target))
	defer local.Close()

	n.log.Debug("датаграммы пошли", "peer", peer.ID, "target", target, "via", via)

	// Считает тот, кто открыл сокет наружу. Через выход это выход, и там же посчитается.
	var m *meter
	if via == ExitViaLocal {
		m = n.meterFor(client)
	}
	splicePackets(local, remote, m)
	m.flush()
	if lost := local.Dropped(); lost > 0 {
		n.log.Warn("пакеты не влезали в датаграмму", "peer", peer.ID, "target", target, "count", lost)
	}
}

// openPackets открывает пакетный путь наружу — здесь или через выходной узел.
//
// Вторым значением возвращается признак маршрута, а не имя узла: клиенту сообщается только
// то, вышел ли поток через выход, — см. ExitVia.
func (n *Node) openPackets(ctx context.Context, target string, viaExit bool, client string) (io.ReadWriteCloser, string, error) {
	if viaExit {
		exit, err := n.cfg.Exits.Pick(ctx)
		if err == nil {
			out, err := exit.OpenUDP(ctx, target, client)
			if err == nil {
				return out, ExitViaEgress, nil
			}
			n.log.Debug("выход не открыл датаграммы, выпускаю у себя",
				"exit", exit.Node(), "target", target, "err", err)
		} else {
			n.log.Debug("выход не найден, выпускаю датаграммы у себя", "err", err)
		}
	}

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	out, err := n.cfg.Dialer.DialContext(dialCtx, "udp", target)
	if err != nil {
		return nil, "", err
	}
	return &socketPackets{conn: out}, ExitViaLocal, nil
}

// socketPackets — внешний пакетный сокет.
//
// Обёртка нужна ради срока простоя: он сдвигается при каждом пакете в любую сторону, и
// молчащий сокет закрывается сам. Без этого ушедший клиент оставлял бы его навсегда — у UDP
// нет ни закрытия соединения, ни признака конца.
type socketPackets struct{ conn net.Conn }

func (s *socketPackets) Read(p []byte) (int, error) {
	_ = s.conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
	return s.conn.Read(p)
}

func (s *socketPackets) Write(p []byte) (int, error) {
	_ = s.conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
	return s.conn.Write(p)
}

func (s *socketPackets) Close() error { return s.conn.Close() }

// datagramStream — то, что умеет слать и принимать датаграммы HTTP.
//
// Под этим и *http3.Stream на узле, и *http3.RequestStream у того, кто просил.
type datagramStream interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

// packetStream — поток HTTP/3, по которому едут датаграммы.
//
// Read и Write здесь пакетные: одно чтение — одна датаграмма. Границы сообщений сохраняются,
// и это не деталь реализации, а требование UDP.
type packetStream struct {
	stream datagramStream
	closer io.Closer
	ctx    context.Context
	cancel context.CancelFunc

	log      *slog.Logger
	saidOnce sync.Once
	dropped  atomic.Int64
}

// newPacketStream собирает пакетную обёртку над потоком.
//
// watch — та сторона потока, по которой видно, что собеседник ушёл. Сами датаграммы об этом
// не сообщают никак, а поток сообщает: пришёл конец — значит закрыли. Без этого чтение
// висело бы до конца соединения, держа за собой и сокет, и горутину.
func newPacketStream(
	ctx context.Context,
	stream datagramStream,
	closer io.Closer,
	watch io.Reader,
	log *slog.Logger,
) *packetStream {
	ctx, cancel := context.WithCancel(ctx)
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	p := &packetStream{stream: stream, closer: closer, ctx: ctx, cancel: cancel, log: log}
	go func() {
		_, _ = io.Copy(io.Discard, watch)
		cancel()
	}()
	return p
}

// Dropped — сколько пакетов не влезло в путь.
func (p *packetStream) Dropped() int64 { return p.dropped.Load() }

func (p *packetStream) Read(b []byte) (int, error) {
	for {
		// Ждать приходится с контекстом: закрытие своей половины потока принимающую сторону
		// не будит, и без отмены чтение осталось бы висеть навсегда.
		msg, err := p.stream.ReceiveDatagram(p.ctx)
		if err != nil {
			return 0, err
		}
		id, n, err := quicvarint.Parse(msg)
		if err != nil || id != contextIDDatagram {
			// Чужой контекст или мусор — теряем ровно эту датаграмму. Рвать из-за неё весь
			// поток незачем: RFC 9298 §5 прямо велит такие пропускать.
			continue
		}
		return copy(b, msg[n:]), nil
	}
}

func (p *packetStream) Write(b []byte) (int, error) {
	out := quicvarint.Append(make([]byte, 0, len(b)+1), contextIDDatagram)
	if err := p.stream.SendDatagram(append(out, b...)); err != nil {
		// Пакет, не влезающий в путь, — потеря одного пакета, а не конец связи: так же он
		// потерялся бы и в обычной сети. Но потеря обязана быть слышной. Приложение, чьи
		// большие пакеты уходят в никуда, для человека выглядит как «работает через раз», и
		// разобраться без единой строки в журнале нечем.
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			p.dropped.Add(1)
			// Один раз за поток: пакеты идут потоком, и жалоба на каждый залила бы журнал.
			p.saidOnce.Do(func() {
				// Потолок называется как есть — это предел всей датаграммы QUIC. Полезной
				// нагрузке достаётся на несколько байт меньше: сверху идут идентификатор
				// потока и контекста. Вычитать их здесь значило бы гадать: длина
				// идентификатора потока известна только слою HTTP.
				p.log.Warn("пакет не влез в датаграмму, потерян",
					"size", len(b), "datagram_limit", tooLarge.MaxDatagramPayloadSize)
			})
			return len(b), nil
		}
		return 0, err
	}
	return len(b), nil
}

func (p *packetStream) Close() error {
	p.cancel()
	return p.closer.Close()
}

// splicePackets гоняет пакеты в обе стороны, пока одна из них не кончится.
//
// От splice для потоков отличается тем, что io.Copy здесь не годится по смыслу: он вправе
// склеить два чтения в одну запись, а для датаграмм это уже другое сообщение.
//
// Байты считаются наравне с потоками, иначе учёт врал бы ровно на игры и разговоры. Пустой
// счётчик означает, что считать не нам: через выход это делает выход.
func splicePackets(local, remote io.ReadWriteCloser, m *meter) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyPackets(local, remote, m.addReceived)
		local.Close()
	}()
	copyPackets(remote, local, m.addSent)
	remote.Close()
	local.Close()
	<-done
}

func copyPackets(dst io.Writer, src io.Reader, add func(uint64)) {
	buf := make([]byte, maxDatagram)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
			add(uint64(n))
		}
		if err != nil {
			return
		}
	}
}

// OpenUDP просит узел открыть пакетный путь до адреса.
//
// Возвращённое соединение пакетное: одно чтение — одна датаграмма.
func (c *Conn) OpenUDP(ctx context.Context, target string, viaExit bool) (io.ReadWriteCloser, error) {
	return c.OpenUDPFor(ctx, target, viaExit, "")
}

// OpenUDPFor открывает пакетный путь, называя, чей это трафик.
func (c *Conn) OpenUDPFor(ctx context.Context, target string, viaExit bool, client string) (io.ReadWriteCloser, error) {
	path, err := udpPath(target)
	if err != nil {
		return nil, err
	}

	stream, err := c.http3.OpenRequestStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("node: открытие потока датаграмм: %w", err)
	}

	// Контекст отмеряет открытие, а поток живёт дольше — как и на прочих каналах.
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx),
		http.MethodConnect, "https://"+c.authority+path, nil)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("node: сборка запроса датаграмм: %w", err)
	}
	// Расширенный CONNECT: значение взято из реестра, своего не изобретаем.
	req.Proto = udpProtocol
	if viaExit {
		req.Header.Set(ExitHeader, ExitYes)
	}
	if client != "" {
		req.Header.Set(ClientHeader, client)
	}

	if err := stream.SendRequestHeader(req); err != nil {
		stream.Close()
		return nil, fmt.Errorf("node: запрос датаграмм: %w", err)
	}
	resp, err := stream.ReadResponse()
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("node: ответ на запрос датаграмм: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		stream.Close()
		return nil, fmt.Errorf("node: узел отказал в %s: %s", target, resp.Status)
	}
	log := c.log
	if log != nil {
		log = log.With("target", target)
	}
	return newPacketStream(context.WithoutCancel(ctx), stream, stream, resp.Body, log), nil
}
