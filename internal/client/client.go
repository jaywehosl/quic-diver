// Package client — ядро клиента, одно на все системы.
//
// Здесь всё, что не зависит от того, где клиент работает: связь с сетью, гонка входных узлов,
// правила, подменные адреса, служба имён, терминация потоков. Различие между Linux, Android и
// Windows сводится к двум вещам — как получить интерфейс и кто расставляет маршруты, — и
// живёт оно в internal/tunnel, а не здесь.
//
// Поэтому телефонное приложение и служба на сервере запускают один и тот же код: первое —
// через тонкую обёртку, отдающую готовый дескриптор от VpnService, второе — через
// cmd/qd-client с разбором флагов.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jaywehosl/quic-diver/internal/geodata"
	"github.com/jaywehosl/quic-diver/internal/link"
	"github.com/jaywehosl/quic-diver/internal/node"
	"github.com/jaywehosl/quic-diver/internal/procmatch"
	"github.com/jaywehosl/quic-diver/internal/routing"
	"github.com/jaywehosl/quic-diver/internal/socks"
)

// Options — всё, чем настраивается клиент.
//
// Экспортируется целиком: телефонное приложение заполняет ту же структуру, что и разбор
// флагов, только вместо имени интерфейса кладёт готовый дескриптор.
type Options struct {
	// Bundle, BundleFile, BundlePassword — откуда клиент узнаёт сеть.
	Bundle         string
	BundleFile     string
	BundlePassword string

	// NodeAddr, NodeKey, ID, KeyHex — один узел вместо бандла, для отладки.
	NodeAddr string
	NodeKey  string
	ID       string
	KeyHex   string

	// Listen — адрес входа SOCKS5. Пустой означает, что вход не поднимается: на телефоне он
	// не нужен вовсе, там весь трафик идёт туннелем.
	Listen  string
	ViaExit bool
	// Control — рычаги для того, что человек двигает при работающем клиенте. Пустой означает,
	// что двигать нечем: так работает клиент из командной строки.
	Control *Control
	// BrutalUp перебивает потолок из бандла. Отрицательное означает «взять из сети».
	BrutalUp int
	// Rules — правила маршрутизации, заданные человеком.
	//
	// На телефоне они приходят отсюда: файла у приложения нет, а список правит экран. Из
	// командной строки берётся RulesPath — там файл естественнее.
	Rules     []routing.Rule
	RulesPath string
	GeoDir    string
	GeoMode   string
	// StateDir — где клиент держит то, что должно пережить перезапуск: сведения о сети,
	// полученные от неё самой. Пустой означает, что помнить негде и узлы каждый раз берутся
	// из ссылки.
	StateDir string

	// TunName — имя интерфейса, который клиент создаёт сам. Пустое означает, что туннеля нет.
	TunName string
	// TunFD — готовый дескриптор интерфейса вместо создания своего.
	//
	// Так работает Android: интерфейс заводит система по запросу приложения, маршруты
	// расставляет тоже она, а нам достаётся дескриптор. Ноль означает обычный путь.
	TunFD       int
	TunAddrs    string
	TunMTU      int
	TunDefault  bool
	TunExcept   string
	TunGuard    int
	FakeRange   string
	DNSUpstream string
	// KeepDNS перехватывает шифрованный DNS: имена известных резолверов DoH получают отказ,
	// соединения на порт DoT обрываются.
	//
	// Без этого браузер разрешает имена сам, минуя туннель, и правила по доменам перестают
	// работать целиком — молча, без единой строки в журнале.
	KeepDNS  bool
	LogLevel string
	// Log — куда писать. Пустой означает вывод в стандартный поток ошибок.
	Log *slog.Logger
	// State — куда клиент складывает состояние для показа человеку. Пустое означает, что
	// состояние никому не нужно: так работает служба на сервере.
	State *State
}

// withDefaults заполняет то, что можно не называть.
func (o Options) withDefaults() Options {
	if o.TunAddrs == "" {
		o.TunAddrs = "10.7.0.2/24"
	}
	if o.TunMTU <= 0 {
		o.TunMTU = 1400
	}
	if o.FakeRange == "" {
		o.FakeRange = "198.18.0.0/15"
	}
	if o.DNSUpstream == "" {
		o.DNSUpstream = "1.1.1.1:53"
	}
	if o.GeoMode == "" {
		o.GeoMode = "off"
	}
	return o
}

// Run поднимает клиента и держит его, пока жив контекст.
func Run(ctx context.Context, o Options) error {
	o = o.withDefaults()

	log := o.Log
	if log == nil {
		log = newLogger(o.LogLevel)
	}

	// Дескриптор интерфейса отдан нам целиком, и закрыть его обязаны мы — на любом пути
	// выхода, а не только на удачном. Путь до туннеля длинный: бандл, гонка узлов, правила,
	// базы; выход по ошибке или по отмене на любом из этих шагов оставлял интерфейс жить
	// вечно, и человек видел висящий значок VPN при снятом туннеле.
	fd := newFDGuard(o.TunFD, log)
	defer fd.close()

	net, err := resolveNetwork(o, log)
	if err != nil {
		return err
	}

	// Сеть, запомненная с прошлого запуска, свежее ссылки: ссылка — слепок на день выдачи, а
	// это — то, что сеть рассказала о себе сама (решение 007 §4).
	memory := &networkMemory{dir: o.StateDir, genesis: net.genesis}
	if saved, ok := loadRemembered(o.StateDir, net.genesis, log); ok {
		memory.known = saved
		net.targets = saved.targets()
		net.hasEgress = saved.Egress
		net.settings = saved.Settings
		log.Info("сеть взята из памяти, а не из ссылки",
			"входных узлов", len(net.targets), "записано",
			time.Unix(saved.SavedUnix, 0).Format(time.RFC3339))
	}

	o.State.SetNetwork(net.name, o.ViaExit && net.hasEgress)

	// Связь держится сама: гонка ко всем входным узлам, а при обрыве — гонка заново. Всё,
	// что выше, переживает смену узла, не зная о ней.
	// Клиент шлёт «вверх»: столько, сколько отдаёт его канал (решение 006). Число приходит
	// из сети, но последнее слово за человеком: свой канал он знает лучше администратора,
	// сидящего в другой стране.
	sendMbps := net.settings.BrutalUpMbps
	if o.BrutalUp >= 0 {
		sendMbps = o.BrutalUp
	}

	conn, err := link.New(link.Config{
		Targets:  net.targets,
		TLS:      &tls.Config{},
		Self:     net.self,
		SendMbps: sendMbps,
		OnConnect: func(c *node.Conn) {
			c.SetLog(log)
			o.State.Connected(c.Peer().ID)
		},
		OnDisconnect: o.State.Disconnected,
		Log:          log,
	})
	switch {
	case sendMbps > 0:
		log.Info("BRUTAL включён", "отдача_мбит", sendMbps,
			"приём_мбит", net.settings.BrutalDownMbps)
	case net.settings.BrutalUpMbps > 0:
		log.Info("BRUTAL выключен флагом, хотя сеть его предлагала",
			"предлагали_мбит", net.settings.BrutalUpMbps)
	}
	if err != nil {
		return err
	}

	memory.link = conn

	linkCtx, stopLink := context.WithCancel(ctx)
	defer stopLink()
	linkDone := make(chan error, 1)
	go func() { linkDone <- conn.Run(linkCtx) }()

	// Первого соединения дожидаемся здесь: без него не выяснить ни правил, ни баз, а
	// поднимать туннель в никуда — верный способ отрезать машину от сети.
	first, err := waitFirst(ctx, conn)
	if err != nil {
		return err
	}
	log.Info("связь с сетью установлена", "node", first.Peer().ID)

	viaExit := o.ViaExit
	if viaExit && !net.hasEgress {
		// Чекбокс включён, а выходных узлов в сети нет. Молчаливо ходить через входной —
		// значит соврать: человек будет считать, что сидит в другой стране.
		log.Warn("выходных узлов в сети нет, весь трафик пойдёт через входной")
		viaExit = false
	}

	// Чекбокс задаёт умолчание, правила переопределяют его для себя.
	fallback := routing.ActionDirect
	if viaExit {
		fallback = routing.ActionEgress
		log.Info("умолчание: через выходные узлы")
	}

	// Правила задаёт человек: списком из приложения либо файлом из командной строки. Сеть их
	// не назначает вовсе — применяет-то их всё равно клиент (ТЗ ст. 36, решение 005).
	rules := o.Rules
	if len(rules) == 0 {
		rules, err = loadRules(o.RulesPath)
		if err != nil {
			return err
		}
	}
	engine, err := routing.New(rules, fallback, log)
	if err != nil {
		return err
	}
	if engine.Len() > 0 {
		log.Info("правила маршрутизации загружены", "rules", engine.Len())
	}

	// С этой минуты галку «через выходные узлы» можно двигать при работающем клиенте.
	o.Control.attach(engine, log)
	defer o.Control.detach()

	// Базы подтягиваются через уже поднятый туннель: напрямую GitHub с машины под
	// фильтрацией может и не открыться.
	if err := setupGeo(ctx, o, conn, engine, viaExit, log); err != nil {
		// Ошибка баз не мешает работе: правила по доменам, подсетям и процессам от них
		// не зависят вовсе.
		log.Warn("базы geosite/geoip недоступны, работаю без них", "err", err)
	}

	// Правила с geosite и geoip без баз не срабатывают никогда. Молчать об этом нельзя:
	// человек будет считать, что реклама режется, а она не режется.
	for _, dead := range engine.Inactive() {
		log.Warn("правило не работает без баз geosite/geoip", "rule", dead)
	}

	// Сеть рассказывает о себе снапшотом: узлы, параметры, расход. Клиент применяет их на лету
	// и запоминает до следующего запуска (решение 007 §4).
	//
	// Владельцу снапшоты не приходят: узел отвечает ему сверкой журналов — тем же обменом,
	// каким сверяются узлы между собой (решение 007 §1.1). Читать этот поток как снапшоты
	// значило бы разбирать чужие кадры и писать в журнал строку на каждый.
	if net.owner {
		log.Info("работаю по ссылке владельца: узлы беру из своего журнала, снапшоты не жду")
	} else {
		go watchSnapshots(ctx, conn, net.genesis, o.State, memory, log)
	}

	finder := procmatch.New()
	if _, err := finder.Lookup(netip.AddrPort{}, netip.AddrPort{}); errors.Is(err, procmatch.ErrUnsupported) {
		// Молчать нельзя по той же причине, что и с базами: человек будет думать, будто
		// правило по процессу работает, а оно не работает.
		for _, r := range rules {
			if usesProcess(r) {
				log.Warn("правила по процессам на этой платформе не работают", "rule", r.Comment)
				break
			}
		}
	}

	// Вход SOCKS поднимается, если его попросили. На телефоне он не нужен вовсе: там нет
	// приложений, которым его настраивают, а весь трафик и так идёт туннелем.
	if o.Listen != "" {
		srv := &socks.Server{
			Addr:   o.Listen,
			Open:   opener{link: conn, engine: engine, log: log},
			Finder: finder,
			Log:    log,
		}
		if o.TunName == "" && o.TunFD == 0 {
			return firstError(srv.ListenAndServe(ctx), linkDone)
		}
		go func() {
			if err := srv.ListenAndServe(ctx); err != nil {
				log.Error("вход SOCKS остановлен", "err", err)
			}
		}()
	}

	if o.TunName == "" && o.TunFD == 0 {
		return fmt.Errorf("клиенту нечего делать: ни входа SOCKS, ни туннеля")
	}
	return firstError(runTunnel(ctx, o, net, conn, engine, fd, log), linkDone)
}

// waitFirst дожидается первого соединения, не давая клиенту ждать вечно молча.
func waitFirst(ctx context.Context, l *link.Link) (*node.Conn, error) {
	waitCtx, cancel := context.WithTimeout(ctx, firstConnectTimeout)
	defer cancel()

	conn, err := l.Conn(waitCtx)
	if err != nil {
		return nil, fmt.Errorf("связь с сетью не установилась за %s: %w", firstConnectTimeout, err)
	}
	return conn, nil
}

// firstConnectTimeout — сколько ждём самого первого соединения.
//
// Дальше связь держится сама и молчит об обрывах, но первая неудача обязана быть громкой:
// человек только что запустил клиент и ждёт ответа, а не тишины.
const firstConnectTimeout = 60 * time.Second

// firstError возвращает беду того, кто упал первым.
//
// Смерть связи и смерть того, что над ней, — разные вещи, и путать их нельзя: клиент,
// сказавший «вход SOCKS остановлен», когда на самом деле кончилась сеть, отправляет человека
// искать не там.
func firstError(err error, linkDone <-chan error) error {
	if err != nil {
		return err
	}
	select {
	case linkErr := <-linkDone:
		return linkErr
	default:
		return nil
	}
}

// setupGeo проверяет свежесть баз, при надобности качает их и отдаёт движку.
//
// Ходит через туннель — тем же путём, что и весь остальной трафик. Отдельного объяснения,
// почему клиент лезет наружу мимо собственной сети, тогда не требуется, а на машине под
// фильтрацией это ещё и единственный способ достучаться до источника.
func setupGeo(
	ctx context.Context,
	o Options,
	l *link.Link,
	engine *routing.Engine,
	viaExit bool,
	log *slog.Logger,
) error {
	dir := o.GeoDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("каталог баз: %w", err)
		}
		dir = filepath.Join(home, ".qdiver", "geo")
	}

	mode, err := geodata.ParseMode(o.GeoMode)
	if err != nil {
		return err
	}

	updater := &geodata.Updater{
		Dir:  dir,
		Mode: mode,
		HTTP: &http.Client{
			Timeout: 3 * time.Minute,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					conn, err := l.Conn(ctx)
					if err != nil {
						return nil, err
					}
					return conn.DialContext(ctx, network, addr, viaExit)
				},
				// Через туннель уже идёт QUIC: второй слой сжатия и мультиплексирования
				// здесь ничего не даст, а вот сюрпризов добавит.
				ForceAttemptHTTP2: false,
			},
		},
		Log: log,
	}

	status := updater.Check(ctx)
	switch {
	case mode == geodata.ModeOff && status.Missing():
		return fmt.Errorf("проверка обновлений выключена, а баз нет")
	case mode == geodata.ModeOff:
		log.Info("проверка обновлений баз выключена", "installed", status.Installed)
	case status.Err != nil:
		log.Warn("свериться с источником не вышло", "err", status.Err)
	case status.Missing():
		log.Info("баз нет, качаю", "version", status.Latest)
		if err := updater.Download(ctx, status.Latest); err != nil {
			return err
		}
	case status.HasUpdate():
		log.Info("вышли свежие базы", "installed", status.Installed, "latest", status.Latest)
		if mode == geodata.ModeAsk && !confirmUpdate(status.Installed, status.Latest) {
			log.Info("обновление баз отложено", "version", status.Installed)
			break
		}
		if err := updater.Download(ctx, status.Latest); err != nil {
			return err
		}
	default:
		log.Info("базы свежие", "version", status.Installed)
	}

	sets, err := updater.Load()
	if err != nil {
		return err
	}
	engine.SetSets(sets)
	log.Info("базы загружены", "stats", sets.Stats())
	return nil
}

// loadRules читает правила из файла. Пустой путь означает, что правил нет вовсе.
func loadRules(path string) ([]routing.Rule, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("правила: %w", err)
	}
	// Метка порядка байтов — обычное дело для редакторов Windows, а JSON от неё падает
	// с невнятным «invalid character 'ï'».
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))

	var rules []routing.Rule
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rules); err != nil {
		return nil, fmt.Errorf("разбор правил: %w", err)
	}
	return rules, nil
}

// opener открывает потоки через соединение с узлом, решая по правилам.
type opener struct {
	link   *link.Link
	engine *routing.Engine
	log    *slog.Logger
}

// usesProcess сообщает, опирается ли правило на имя процесса.
func usesProcess(r routing.Rule) bool {
	for _, m := range r.Match {
		if strings.HasPrefix(strings.ToLower(m), "process:") {
			return true
		}
	}
	return false
}

func (o opener) Open(ctx context.Context, target string, from socks.Source) (io.ReadWriteCloser, error) {
	flow := flowOf(target)
	flow.Process = from.Process
	decision := o.engine.Decide(flow)

	if decision.Action == routing.ActionBlock {
		o.log.Debug("поток заблокирован", "target", target, "by", decision.String())
		return nil, fmt.Errorf("routing: %s заблокирован (%s)", target, decision)
	}

	// Соединение спрашивается на каждый поток: за время работы клиента узел мог смениться,
	// и держать ссылку на прежний значило бы слать потоки в мёртвую связь.
	conn, err := o.link.Conn(ctx)
	if err != nil {
		return nil, err
	}

	viaExit := decision.Action == routing.ActionEgress
	stream, err := conn.OpenVia(ctx, target, viaExit)
	if err != nil {
		return nil, err
	}

	// Узел сообщает, через кого поток вышел на самом деле. Выход на входном узле, когда
	// просили через выходной, — не ошибка, а запасной путь: связь важнее. Но человек
	// должен видеть это в журнале, а не узнавать по чужому адресу на сайте.
	switch {
	case viaExit && !stream.ViaEgress():
		o.log.Warn("выходные узлы недоступны, поток вышел на входном",
			"target", target, "by", decision.String())
	default:
		o.log.Debug("поток вышел", "target", target,
			"через_выход", stream.ViaEgress(), "by", decision.String())
	}
	return stream, nil
}

// flowOf разбирает адрес из запроса SOCKS в то, по чему решают правила.
//
// Имя здесь известно, когда приложение попросило соединиться по имени, а не по адресу —
// то есть почти всегда. Это как раз то, чего не хватает при работе с голыми пакетами.
func flowOf(target string) routing.Flow {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return routing.Flow{Domain: target}
	}
	flow := routing.Flow{}
	if port, err := strconv.ParseUint(portStr, 10, 16); err == nil {
		flow.Port = uint16(port)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		flow.Addr = addr
	} else {
		flow.Domain = host
	}
	return flow
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
