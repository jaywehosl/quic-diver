package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/quicx"
)

// Потоки трафика.
//
// Клиент терминирует соединения у себя и просит узел открыть обычный TCP наружу. Делается
// это методом CONNECT по RFC 9114 §4.4 — тем же самым, которым HTTP-прокси работают
// десятилетиями. Ничего своего не изобретается, и трафик выглядит ровно так, как выглядит
// прокси-соединение любого другого приложения.
//
// Расширенный CONNECT со своим значением :protocol сюда не годится (см. node.go): значения
// берутся из реестра HTTP Upgrade Token, и своё было бы отклонением от стандарта. Обычный
// CONNECT в реестре не нуждается.

const (
	// plainProto — то, что http3 проставляет запросу без :protocol, то есть обычному.
	plainProto = "HTTP/3.0"

	// dialTimeout — сколько узел ждёт соединения с внешним адресом.
	dialTimeout = 15 * time.Second
	// idleTimeout — сколько поток может молчать, прежде чем узел его закроет.
	idleTimeout = 5 * time.Minute
)

// Dialer открывает соединение наружу. Подменяется в тестах и на выходном узле.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// serveConnect выпускает поток наружу.
//
// Опознание берётся из таблицы сессий: приветствие уже прошло на управляющем потоке того же
// соединения. Неопознанный получает ровно то же, что и всякий посторонний, — страницу
// заглушки, и по ней невозможно понять, что этот узел вообще умеет CONNECT.
func (n *Node) serveConnect(w http.ResponseWriter, r *http.Request) {
	// Расширенный CONNECT приходит тем же методом, отличаясь только значением :protocol.
	// Датаграммы — единственное такое значение, которое узел принимает.
	if r.Proto == udpProtocol {
		n.serveConnectUDP(w, r)
		return
	}
	// Прочие значения :protocol узел не умеет. Молча считать их обычным CONNECT нельзя:
	// у расширенного другой смысл и непустой :path, и получилось бы соединение не туда.
	if r.Proto != plainProto {
		n.reject(w, r, "неизвестный :protocol "+r.Proto)
		return
	}
	if r.TLS == nil {
		n.reject(w, r, "нет состояния TLS")
		return
	}
	binding, err := quicx.Binding(*r.TLS)
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

	target := r.Host
	if target == "" {
		target = r.URL.Host
	}
	if err := validTarget(target); err != nil {
		n.reject(w, r, "негодная цель: "+err.Error())
		return
	}

	// Метка маршрута приходит от клиента и означает ровно одно: выпустить через выходной
	// узел, а не здесь. Какой именно выходной — решит гонка. Едет метка внутри
	// установленного соединения, так что снаружи её не видно; заголовок здесь — обычный
	// способ сказать это в HTTP, ничего своего не изобретается.
	if r.Header.Get(ExitHeader) == ExitYes && n.cfg.Exits != nil {
		n.serveViaExit(w, r, target, clientOf(peer, r))
		return
	}

	n.log.Debug("поток открыт", "peer", peer.ID, "target", target)
	n.serveDirect(w, r, target, ExitViaLocal, clientOf(peer, r))
}

// markActive отмечает, что клиент работает, — на первом же его прикладном запросе.
//
// Решение 001 §2 велит объявлять сессию именно так, а не по приветствию: гонка рукопожатий
// здоровается со всеми адресами всех входных узлов сразу, и все эти приветствия сходятся.
// Считать их работой означало бы, что клиент сам себе накрутил лимит устройств в разы.
func (n *Node) markActive(binding []byte, peer *hello.Peer) {
	if n.cfg.Sessions == nil || peer.Role != hello.RoleClient {
		return
	}
	device, addr, first := n.sessions.activate(binding)
	if !first {
		return
	}
	n.cfg.Sessions.Active(peer.ID, device, addr, key(binding))
	n.log.Debug("клиент приступил к работе", "id", peer.ID, "device", device, "from", addr)
}

// clientOf выясняет, чей это трафик.
//
// Клиент назвался приветствием, и его слову о себе верить не нужно — оно уже проверено
// подписью. Сосед же пересылает чужой поток, и чей он, знает только сосед: сокет наружу
// откроем мы, а клиента у нас нет. Поэтому от узла заголовок принимается, а от клиента —
// никогда: иначе любой писал бы расход на чужой счёт.
func clientOf(peer *hello.Peer, r *http.Request) string {
	if peer.Role == hello.RoleNode {
		return r.Header.Get(ClientHeader)
	}
	return peer.ID
}

// bindingOf достаёт привязку к TLS-сессии из запроса.
func bindingOf(r *http.Request) ([]byte, error) {
	if r.TLS == nil {
		return nil, errors.New("node: нет состояния TLS")
	}
	return quicx.Binding(*r.TLS)
}

// ExitHeader — заголовок, которым клиент просит выпустить поток через выходной узел.
//
// Значение у него одно, потому что и выбор один: наружу здесь или наружу через выход.
// Какой именно выход — не спрашивают: их выбирает гонка.
const ExitHeader = "Qd-Exit"

// ExitYes — единственное осмысленное значение ExitHeader.
const ExitYes = "1"

// ClientHeader — чей это трафик.
//
// Ставит его входной узел, пересылая поток на выходной: сокет наружу открывает выход, ему и
// считать байты, а клиента он не знает (решение 001 §2). Заголовок едет внутри уже
// установленного соединения между узлами и снаружи не виден.
//
// От клиента этот заголовок не принимается: клиент опознан приветствием, и верить его слову
// о том, кто он, — значит позволить любому писать расход на чужой счёт.
const ClientHeader = "Qd-Client"

// ExitVia — заголовок ответа: вышел поток через выходной узел или здесь же.
//
// Нужен затем, что запасной путь молчаливым быть не должен. Если выхода не нашлось, поток
// выпускается на входном узле — связь важнее страны, — но клиент обязан узнать об этом, а не
// думать, будто сидит в Варшаве, находясь в Москве.
//
// Имени выходного узла здесь нет намеренно. Клиенту оно не нужно ни для чего: выход выбирает
// гонка на входном узле, и повлиять на выбор клиент не может. А назвать имя означало бы
// раздать карту выходной части сети каждому, кто открыл хоть один поток, — при том что бандл
// эту часть скрывает и отдаёт лишь метку о её существовании.
const ExitVia = "Qd-Via"

// Значения ExitVia.
const (
	// ExitViaEgress — поток вышел на выходном узле, как и просили.
	ExitViaEgress = "egress"
	// ExitViaLocal — поток вышел на том узле, к которому подключён клиент.
	ExitViaLocal = "local"
)

// ExitPicker выбирает выходной узел. За ним стоит гонка по тёплым связям.
type ExitPicker interface {
	Pick(ctx context.Context) (Exit, error)
}

// Exit — выбранный выходной узел.
//
// client везде — чей это трафик. Выход открывает сокет наружу, ему и считать байты, а сам он
// клиента не знает: имя приходит от входного узла.
type Exit interface {
	// Open открывает поток до адреса через этот узел.
	Open(ctx context.Context, target, client string) (io.ReadWriteCloser, error)
	// OpenUDP открывает пакетный путь до адреса через этот узел. Одно чтение — одна
	// датаграмма: границы сообщений для UDP и есть содержание.
	OpenUDP(ctx context.Context, target, client string) (io.ReadWriteCloser, error)
	// Node — идентификатор узла, для заголовка ответа и для журнала.
	Node() string
}

// counter считает байты по мере того, как они проходят.
type counter struct {
	w   io.Writer
	add func(uint64)
}

func (c counter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.add(uint64(n))
	}
	return n, err
}

// Meter учитывает трафик клиента.
//
// Считает тот узел, который открыл сокет наружу, и только он: при работе через выход входной
// узел не считает ничего, иначе один и тот же байт попал бы в счёт дважды.
type Meter interface {
	// Count добавляет к расходу клиента. sent — наружу, received — обратно.
	Count(client string, sent, received uint64)
}

// serveViaExit выпускает поток через выходной узел, выбранный гонкой.
func (n *Node) serveViaExit(w http.ResponseWriter, r *http.Request, target, client string) {
	ctx := r.Context()

	exit, err := n.cfg.Exits.Pick(ctx)
	if err != nil {
		// Выходов нет или все молчат — выпускаем у себя и честно об этом сообщаем.
		n.log.Debug("выход не найден, выпускаю у себя", "err", err)
		n.serveDirect(w, r, target, ExitViaLocal, client)
		return
	}

	stream, err := exit.Open(ctx, target, client)
	if err != nil {
		n.log.Debug("выход не открыл поток, выпускаю у себя",
			"exit", exit.Node(), "target", target, "err", err)
		n.serveDirect(w, r, target, ExitViaLocal, client)
		return
	}
	defer stream.Close()

	w.Header().Set(ExitVia, ExitViaEgress)
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	n.log.Debug("поток пошёл через выход", "exit", exit.Node(), "target", target)
	// Байты здесь не считаются намеренно: сокет наружу открыл выход, он их и посчитает.
	// Посчитать и тут значило бы записать один и тот же байт дважды.
	from := &duplex{r: r.Body, w: w}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(from, stream)
	}()
	_, _ = io.Copy(stream, from)

	// Клиент договорил — надо сказать об этом выходу, иначе он будет ждать продолжения, а мы
	// ждать его ответа. Оба висели бы до таймаута, и до записи расхода дело дошло бы через
	// минуты после того, как человек закрыл вкладку.
	if cw, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	<-done
}

// serveDirect выпускает поток на этом узле.
func (n *Node) serveDirect(w http.ResponseWriter, r *http.Request, target, via, client string) {
	ctx, cancel := context.WithTimeout(r.Context(), dialTimeout)
	defer cancel()

	out, err := n.cfg.Dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		n.cfg.Decoy.Error(w, r, http.StatusBadGateway)
		return
	}
	defer out.Close()

	w.Header().Set(ExitVia, via)
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	meter := n.meterFor(client)
	sent, received := splice(&duplex{r: r.Body, w: w}, out, meter)
	meter.flush()
	n.log.Debug("расход записан", "client", client, "наружу", sent, "обратно", received)
}

// flushEvery — сколько байт копится, прежде чем уйти в учёт.
//
// Считать на каждую запись значило бы брать замок на каждый пакет; копить до конца потока —
// проглядеть того, кто качает пятьдесят гигабайт одним соединением и не закрывает его. Между
// этими крайностями и лежит порог.
const flushEvery = 64 << 10

// meter копит байты потока и сдаёт их в учёт порциями.
//
// Под замком: половины потока копируются в разных горутинах и прибавляют сюда одновременно.
type meter struct {
	client string
	to     Meter
	log    *slog.Logger

	mu             sync.Mutex
	sent, received uint64
}

func (n *Node) meterFor(client string) *meter {
	return &meter{client: client, to: n.cfg.Meter, log: n.log}
}

// addSent и addReceived прибавляют байты, сдавая накопленное при переполнении порога.
//
// Пустой счётчик молчит: так помечается поток, который считает не этот узел.
func (m *meter) addSent(v uint64) { m.add(v, 0) }

func (m *meter) addReceived(v uint64) { m.add(0, v) }

func (m *meter) add(sent, received uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.sent += sent
	m.received += received
	full := m.sent+m.received >= flushEvery
	m.mu.Unlock()

	if full {
		m.flush()
	}
}

// flush сдаёт накопленное.
func (m *meter) flush() {
	if m == nil || m.to == nil {
		return
	}

	m.mu.Lock()
	sent, received := m.sent, m.received
	m.sent, m.received = 0, 0
	m.mu.Unlock()

	if sent == 0 && received == 0 {
		return
	}
	if m.client == "" {
		// Поток без имени клиента — трафик, который никому не запишется. У соседа это
		// значит, что он не назвал клиента; молчать нельзя, иначе расход тихо теряется.
		m.log.Debug("поток без имени клиента, расход не записан",
			"наружу", sent, "обратно", received)
		return
	}
	m.to.Count(m.client, sent, received)
}

// splice гоняет байты в обе стороны, пока одна из них не кончится.
//
// Байты сдаются в учёт по ходу дела, а не по завершении: поток живёт сколько угодно долго, и
// счёт «в конце» означал бы, что качающий пятьдесят гигабайт одним соединением не виден
// учёту вовсе, пока не закончит.
func splice(client io.ReadWriter, remote net.Conn, m *meter) (sent, received int64) {
	done := make(chan struct{})

	go func() {
		defer close(done)
		received, _ = io.Copy(counter{w: client, add: m.addReceived}, remote)
	}()

	sent, _ = io.Copy(counter{w: remote, add: m.addSent}, client)
	// Дочитывать бесконечно нельзя: закрыв запись наружу, мы сообщаем той стороне, что
	// говорить больше не будем, и она отвечает своим закрытием.
	if cw, ok := remote.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = remote.SetReadDeadline(time.Now().Add(idleTimeout))
	}
	<-done
	return sent, received
}

// validTarget не пускает узел куда попало по чужой просьбе.
//
// Проверяется здесь только форма адреса. Куда именно можно ходить — вопрос правил
// маршрутизации, а не транспорта, и решается он выше.
func validTarget(target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("нужен host:port: %w", err)
	}
	if host == "" {
		return errors.New("пустой адрес")
	}
	if port == "" || strings.ContainsAny(port, "abcdefghijklmnopqrstuvwxyz") {
		return fmt.Errorf("негодный порт %q", port)
	}
	return nil
}

// systemDialer — обычный набор номера через стек операционной системы.
type systemDialer struct{ d net.Dialer }

func newSystemDialer() Dialer {
	return &systemDialer{d: net.Dialer{
		Timeout: dialTimeout,
		// Happy Eyeballs (RFC 8305): у выходного узла обычно есть и v4, и v6, и ждать
		// таймаута по одному семейству, когда работает другое, незачем.
		FallbackDelay: 300 * time.Millisecond,
	}}
}

func (s *systemDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.d.DialContext(ctx, network, addr)
}

// Resolver разрешает имена. За ним стоит резолвер узла со своим кешем.
type Resolver interface {
	// Resolve возвращает адреса имени. network — "ip4", "ip6" или "ip".
	Resolve(ctx context.Context, name, network string) ([]netip.Addr, error)
}

// resolvingDialer ходит наружу, разрешая имена своим резолвером.
//
// Нужен затем, что имя разрешает именно узел: клиент присылает имя, а не адрес, и всё —
// кеш, первичный и вторичный адреса, переопределение времени жизни — работает здесь.
// Системный резолвер не умеет ничего из этого.
type resolvingDialer struct {
	resolver Resolver
	d        net.Dialer
}

func newResolvingDialer(r Resolver) Dialer {
	return &resolvingDialer{
		resolver: r,
		d: net.Dialer{
			Timeout:       dialTimeout,
			FallbackDelay: 300 * time.Millisecond,
		},
	}
}

func (r *resolvingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("node: адрес %q: %w", addr, err)
	}

	addrs, err := r.resolver.Resolve(ctx, host, familyOf(network))
	if err != nil {
		return nil, err
	}

	// Адреса перебираются по очереди. Имя с несколькими адресами — обычное дело, и отказ
	// первого не повод считать сайт недоступным.
	var errs []error
	for _, a := range addrs {
		conn, err := r.d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("node: ни один адрес %s не отозвался: %w", host, errors.Join(errs...))
}

// familyOf переводит сеть Go в семейство адресов.
func familyOf(network string) string {
	switch network {
	case "tcp4", "udp4":
		return "ip4"
	case "tcp6", "udp6":
		return "ip6"
	default:
		return "ip"
	}
}
