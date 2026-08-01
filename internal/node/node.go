// Package node — слушатель узла: один порт, один сертификат, два исхода.
//
// Снаружи узел — сайт на HTTP/3. Кто пришёл без приветствия, получает заглушку и обычные
// страницы ошибок; кто предъявил подпись — управляющий поток внутри того же соединения.
// Отдельных портов и отдельных демонов нет, как и требует ТЗ.
//
// # Почему управляющий канал — обычный запрос
//
// Напрашивался расширенный CONNECT (RFC 9220) со своим значением :protocol. От него
// отказались: RFC 8441 §4 требует брать значение из реестра HTTP Upgrade Token, и свой
// токен был бы отклонением от стандарта — ровно тем, чего проект избегает. Поэтому
// управляющий канал это обычный запрос с дуплексным телом, а расширенный CONNECT остаётся
// для трафика, где значения зарегистрированы: connect-udp (RFC 9298) и connect-ip (RFC 9484).
package node

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/jaywehosl/quic-diver/internal/decoy"
	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/quicx"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// DeviceHeader — чем устройство клиента себя называет.
//
// Едет заголовком на управляющем канале, а не в приветствии: приветствие — подписанный
// формат с версией, и менять его ради поля, которое всё равно вычисляет сам клиент, не
// стоит. Подписи здесь не нужно и по существу: обмануть этим полем можно только собственный
// лимит устройств (см. internal/hwid).
const DeviceHeader = "Qd-Device"

// ControlPath — путь управляющего канала.
//
// Он не секрет и секретом быть не должен: стойкость держится на подписи, а не на незнании
// пути. Посторонний, попавший сюда, получает такой же 404, как на любом другом адресе.
const ControlPath = "/qd/v1/control"

// maxGreeting ограничивает приветствие: оно приходит от стороны, которая себя ещё ничем не
// подтвердила.
const maxGreeting = 4 << 10

// greetingTimeout — сколько ждём приветствия. Молчащее соединение не должно занимать узел:
// именно так выглядит и сканер, и оборванная связь.
const greetingTimeout = 10 * time.Second

// Control — что делать с опознанным собеседником.
//
// stream живёт, пока обработчик не вернётся: чтение идёт из тела запроса, запись — в тело
// ответа, и в HTTP/3 это полноценный дуплекс.
type Control func(ctx context.Context, peer *hello.Peer, stream io.ReadWriter) error

// Config — что нужно узлу, чтобы слушать.
type Config struct {
	// Addr — адрес прослушивания, обычно ":443".
	Addr string
	// TLS — настоящий сертификат домена. Тот же, что предъявляется заглушке.
	TLS *tls.Config
	// Identity — кем узел представляется в ответном приветствии.
	Identity hello.Identity
	// Directory — чем проверяются чужие подписи.
	Directory hello.Directory
	// Decoy — сайт для посторонних. Пустой означает заглушку по умолчанию.
	Decoy *decoy.Site
	// Control — обработчик опознанного собеседника.
	Control Control
	// Dialer — чем узел выходит наружу. Пустой означает обычный набор через стек ОС.
	Dialer Dialer
	// Resolver — чем узел разрешает имена. Пустой означает системный резолвер: без кеша,
	// без своих адресов, без переопределения времени жизни. Игнорируется, если задан Dialer.
	Resolver Resolver
	// OnRace отвечает на предложения гонки. Пустой означает, что узел в гонках не участвует.
	OnRace func(from string, msg []byte) ([]byte, error)
	// Exits выбирает выходной узел по категории. Пустой означает, что узел выпускает
	// потоки только у себя.
	Exits ExitPicker
	// SendMbps — потолок BRUTAL для отправки клиентам (решение 006). Это «вниз» из настроек
	// сети: узел шлёт клиенту столько, сколько тот в состоянии принять. Ноль означает
	// обычный Cubic.
	SendMbps int
	// Import принимает первый залив журнала, пока узел пуст. Пустой означает, что залив по
	// сети не поддерживается и журнал приходит только файлом.
	Import Importer
	// Introduce отдаёт то, чем узел представляется до включения в сеть: имя, домен, ключ.
	// Пустой означает, что узел не представляется вовсе.
	Introduce func() Introduction
	// Meter учитывает трафик. Пустой означает, что расход не считается.
	Meter Meter
	// Sessions решает, пускать ли клиента, и следит за тем, кто работает. Пустой означает,
	// что лимиты не проверяются вовсе.
	Sessions Sessions
	// Log — куда писать. Пустой означает slog.Default().
	Log *slog.Logger
	// Now подменяет часы в тестах.
	Now func() time.Time
}

// Node — слушающий узел.
type Node struct {
	cfg      Config
	srv      *http3.Server
	log      *slog.Logger
	now      func() time.Time
	sessions *sessions
}

// New собирает узел.
func New(cfg Config) (*Node, error) {
	if cfg.TLS == nil {
		return nil, errors.New("node: не задан TLS")
	}
	if cfg.Identity.Signer == nil {
		return nil, errors.New("node: не задан ключ узла")
	}
	if cfg.Directory == nil {
		return nil, errors.New("node: не задан справочник ключей")
	}
	if cfg.Decoy == nil {
		cfg.Decoy = decoy.New()
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Dialer == nil {
		if cfg.Resolver != nil {
			cfg.Dialer = newResolvingDialer(cfg.Resolver)
		} else {
			cfg.Dialer = newSystemDialer()
		}
	}

	tlsConf := cfg.TLS.Clone()
	// ALPN только h3: свой отличал бы наши узлы от любого другого сайта на HTTP/3.
	tlsConf.NextProtos = []string{quicx.ALPN}

	n := &Node{cfg: cfg, log: cfg.Log, now: cfg.Now, sessions: newSessions()}
	n.srv = &http3.Server{
		Addr:            cfg.Addr,
		TLSConfig:       tlsConf,
		QUICConfig:      quicx.ClientConfig(cfg.SendMbps),
		Handler:         n,
		EnableDatagrams: true,
	}
	return n, nil
}

// ListenAndServe поднимает узел на UDP.
func (n *Node) ListenAndServe() error { return n.srv.ListenAndServe() }

// Serve обслуживает готовый слушатель — так узел поднимают тесты и так же его можно
// посадить на сокет, полученный извне.
func (n *Node) Serve(ln *quic.EarlyListener) error { return n.srv.ServeListener(ln) }

// Close останавливает узел.
func (n *Node) Close() error { return n.srv.Close() }

// ServeHTTP разводит своих и посторонних.
func (n *Node) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		n.serveConnect(w, r)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == ControlPath {
		n.serveControl(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == RacePath {
		n.serveRace(w, r)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == BootstrapPath {
		n.serveBootstrap(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == BootstrapPath {
		n.serveIntroduce(w, r)
		return
	}
	if decoy.IsProbe(r) {
		// Только запись в журнал. Ответ обязан остаться таким же, как на любой другой
		// неизвестный путь: разница в реакции и есть то, что выдаёт узел.
		n.log.Debug("прощупывание", "path", r.URL.Path, "from", r.RemoteAddr)
	}
	n.cfg.Decoy.ServeHTTP(w, r)
}

// serveControl принимает приветствие и, если оно сошлось, отдаёт управляющий поток.
//
// Любая неудача заканчивается одинаково — страницей «не найдено». Ни причина, ни сам факт
// того, что этот путь чем-то отличается от прочих, наружу не выходит.
func (n *Node) serveControl(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		n.reject(w, r, "нет состояния TLS")
		return
	}
	binding, err := quicx.Binding(*r.TLS)
	if err != nil {
		n.reject(w, r, "нет привязки к сессии: "+err.Error())
		return
	}

	body := http.MaxBytesReader(w, r.Body, maxGreeting)
	if rc, ok := w.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = rc.SetReadDeadline(n.now().Add(greetingTimeout))
	}

	peer, err := hello.Recognize(body, binding, n.cfg.Directory, n.now())
	if err != nil {
		n.reject(w, r, "приветствие не принято: "+err.Error())
		return
	}
	if rc, ok := w.(interface{ SetReadDeadline(time.Time) error }); ok {
		// Дальше поток живёт своей жизнью: срок, отведённый на приветствие, снимаем.
		_ = rc.SetReadDeadline(time.Time{})
	}

	// Лимиты проверяются здесь, до ответа: клиент, которому отказано, не должен увидеть
	// разницы с посторонним. Узлы проверке не подлежат — их пускает журнал.
	device, addr := r.Header.Get(DeviceHeader), addrOf(r)
	if peer.Role == hello.RoleClient && n.cfg.Sessions != nil {
		if ok, reason := n.cfg.Sessions.Admit(peer.ID, device, addr); !ok {
			n.log.Info("клиенту отказано", "id", peer.ID, "device", device,
				"from", addr, "reason", reason)
			n.reject(w, r, "лимит: "+reason)
			return
		}
	}

	// Соединение отмечается опознанным ДО ответа. Собеседник, получив наше приветствие,
	// сразу открывает потоки и каналы — и застаёт узел готовым, а не врасплох.
	//
	// Работающим оно станет позже, на первом прикладном запросе: сюда доходят и проигравшие
	// гонку, а они уйдут, не открыв ни одного потока.
	var onGone func()
	if peer.Role == hello.RoleClient && n.cfg.Sessions != nil {
		onGone = func() { n.cfg.Sessions.Gone(peer.ID, key(binding)) }
	}
	forget := n.sessions.add(binding, peer, device, addr, onGone)
	defer forget()

	if err := hello.Respond(&duplex{r: body, w: w}, binding, n.cfg.Identity, n.now()); err != nil {
		n.log.Debug("ответное приветствие не ушло", "id", peer.ID, "err", err)
		return
	}

	n.log.Info("опознан", "role", peer.Role.String(), "id", peer.ID, "from", r.RemoteAddr)
	if n.cfg.Control == nil {
		<-r.Context().Done()
		return
	}
	if err := n.cfg.Control(r.Context(), peer, &duplex{r: r.Body, w: w}); err != nil && !isDone(err) {
		n.log.Warn("управляющий поток завершился ошибкой", "id", peer.ID, "err", err)
	}
}

// Sessions решает, пускать ли клиента, и следит за тем, кто работает.
//
// conn — метка соединения. Она в ключе потому, что одно устройство держит несколько
// соединений сразу: гонка рукопожатий оставляет по одному на каждый адрес каждого входного
// узла. Без метки уход любого из них убирал бы запись, поставленную другим.
type Sessions interface {
	// Admit решает, пускать ли. Отказ объясняется — но только в журнал узла: клиенту
	// причина не сообщается, он видит то же, что и посторонний.
	Admit(client, device, addr string) (ok bool, reason string)
	// Active отмечает, что устройство клиента работает на этом узле.
	Active(client, device, addr, conn string)
	// Gone отмечает уход соединения.
	Gone(client, conn string)
}

// addrOf достаёт адрес собеседника без порта: лимит считает адреса, а не соединения.
func addrOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// reject отвечает ровно то, что ответил бы сайт-заглушка на этот самый запрос.
//
// Отдавать здесь фиксированный 404 нельзя, и это не теория: POST на обычный путь даёт 405,
// потому что статика умеет только чтение. Фиксированный 404 на управляющем пути отличал бы
// его от всех остальных — подбор одним запросом. Поэтому ответ строит тот же обработчик,
// что обслуживает посторонних.
func (n *Node) reject(w http.ResponseWriter, r *http.Request, reason string) {
	n.log.Debug("отказ на управляющем канале", "reason", reason, "from", r.RemoteAddr)
	n.cfg.Decoy.ServeHTTP(w, r)
}

func isDone(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, context.Canceled)
}

// duplex склеивает чтение и запись в один поток.
//
// Захватывать стрим через http3.HTTPStreamer не нужно: в HTTP/3 сервер вправе писать своё
// тело, пока клиент ещё пишет своё. Нужен только Flush после записи — иначе ответ ждёт
// накопления буфера, а собеседник ждёт ответа.
type duplex struct {
	r io.Reader
	w io.Writer
}

func (d *duplex) Read(p []byte) (int, error) { return d.r.Read(p) }

func (d *duplex) Write(p []byte) (int, error) {
	n, err := d.w.Write(p)
	if err != nil {
		return n, err
	}
	if f, ok := d.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, nil
}
