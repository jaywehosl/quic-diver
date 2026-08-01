package client

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jaywehosl/quic-diver/internal/dnsproxy"
	"github.com/jaywehosl/quic-diver/internal/fakeip"
	"github.com/jaywehosl/quic-diver/internal/link"
	"github.com/jaywehosl/quic-diver/internal/routing"
	"github.com/jaywehosl/quic-diver/internal/tunnel"
)

// Режим туннеля.
//
// Отличие от входа SOCKS одно, но существенное: там приложение само называет имя, а здесь из
// пакетов виден только адрес. Пока правила по доменам в этом режиме работают лишь тогда, когда
// адрес попал в правило по подсети; имя появится вместе с перехватом DNS и подменными
// адресами — следующим кирпичом.

// tunHandler решает судьбу соединений, пришедших из туннеля.
//
// Соединение с узлом спрашивается на каждый поток, а не берётся один раз: узел под клиентом
// меняется, когда рвётся связь, и туннель обязан это пережить, не заметив.
type tunHandler struct {
	link    *link.Link
	engine  *routing.Engine
	pool    *fakeip.Pool
	dns     *dnsproxy.Server
	state   *State
	control *Control
	// keepDNS обрывает шифрованный DNS: без этого браузер разрешает имена сам, мимо туннеля,
	// и правила по доменам перестают работать целиком.
	keepDNS bool
	log     *slog.Logger
}

// resolve разворачивает подменный адрес обратно в имя и решает судьбу потока.
//
// Ради этого всё и затевалось: из пакета имени не видно, а правило по домену без имени не
// работает.
//
// # Настоящий адрес
//
// Подменный адрес в правила не отдаётся: условие по подсети сработало бы на служебный
// диапазон вместо настоящего расположения сайта. Но и пустой адрес не годится — с ним условия
// `geoip:` и `ip:` не совпадают никогда, и правило «российское — напрямую» молча ничего не
// делает, хотя человек его написал и видит на экране.
//
// Поэтому, когда такие правила есть, настоящий адрес узнаётся у резолвера и запоминается
// рядом с подменным. Ходить приходится один раз на имя, и только если это на что-то влияет:
// движок отвечает на NeedsAddr, и при правилах по именам да процессам похода не будет вовсе.
func (h tunHandler) resolve(ctx context.Context, target netip.AddrPort, mayAsk bool) (name string, isFake bool, decision routing.Decision, ok bool) {
	if h.pool != nil && h.pool.Contains(target.Addr()) {
		name, isFake = h.pool.Lookup(target.Addr())
		if !isFake {
			// Адрес из нашего диапазона, но аренды нет: приложение держало его дольше, чем
			// мы помним. Вести соединение некуда.
			return "", false, routing.Decision{}, false
		}
	}

	flow := routing.Flow{Domain: name, Addr: target.Addr(), Port: target.Port()}
	if isFake {
		flow.Addr = h.realAddr(ctx, name, target.Addr(), mayAsk)
	}
	return name, isFake, h.engine.Decide(flow), true
}

// realAddr добывает настоящий адрес имени, если он кому-то нужен.
//
// mayAsk разрешает поход к резолверу. Из Allow он запрещён: тот отвечает на SYN и обязан
// отвечать сразу — задержка там означает не «подумали», а «соединение зависло». Оттуда
// работает только то, что уже известно; полное решение принимается на открытии потока,
// мгновением позже.
//
// Пустой ответ — обычное дело: правил по адресу нет, резолвер не ответил, имени нет вовсе. Во
// всех этих случаях решение принимается по имени и умолчанию, как и раньше.
func (h tunHandler) realAddr(ctx context.Context, name string, fake netip.Addr, mayAsk bool) netip.Addr {
	if name == "" || h.pool == nil || !h.engine.NeedsAddr() {
		return netip.Addr{}
	}

	if known := h.pool.Real(fake); len(known) > 0 {
		return known[0]
	}
	if !mayAsk || h.dns == nil {
		return netip.Addr{}
	}

	addrs, err := h.dns.ResolveA(ctx, name)
	if err != nil || len(addrs) == 0 {
		h.log.Debug("настоящий адрес имени не выяснен", "name", name, "err", err)
		return netip.Addr{}
	}
	h.pool.SetReal(name, addrs)
	return addrs[0]
}

// Allow отвечает стеку, стоит ли вообще отвечать на SYN.
//
// Отказ здесь превращается в RST: приложение получает отказ мгновенно, как и требует ТЗ.
// Решать после установления соединения было бы поздно — для браузера это уже не
// «заблокировано», а «сброшено», и он будет пробовать снова.
func (h tunHandler) Allow(target netip.AddrPort) bool {
	// DNS over TLS уходит мимо нас обычным соединением, и тогда у потоков не будет имён —
	// правила по доменам перестают работать целиком. Отказ приходит сбросом, и приложение
	// возвращается к системному резолверу, то есть к нам.
	if h.keepDNS && target.Port() == dnsproxy.DoTPort {
		h.log.Debug("шифрованный DNS отклонён", "target", target.String(), "port", "853")
		return false
	}

	name, _, decision, ok := h.resolve(context.Background(), target, false)
	if !ok {
		h.log.Debug("подменный адрес без аренды", "addr", target.Addr().String())
		return false
	}
	if decision.Action == routing.ActionBlock {
		h.log.Debug("соединение отклонено", "target", describe(name, target), "by", decision.String())
		return false
	}
	return true
}

func (h tunHandler) HandleTCP(ctx context.Context, conn io.ReadWriteCloser, target netip.AddrPort) {
	name, isFake, decision, ok := h.resolve(ctx, target, true)
	if !ok || decision.Action == routing.ActionBlock {
		// Сюда уже не должно доходить: решение принято в Allow. Но если дошло — рвём.
		return
	}

	// Узлу отправляется имя, если оно известно: он разрешит его сам и выйдет по тому
	// семейству адресов, которое у имени есть. Так домен, живущий только в IPv6,
	// открывается с машины, где IPv6 нет вовсе.
	dest := target.String()
	if isFake {
		dest = net.JoinHostPort(name, strconv.Itoa(int(target.Port())))
	}

	up, err := h.link.Conn(ctx)
	if err != nil {
		h.log.Debug("связи с сетью нет", "target", dest, "err", err)
		return
	}
	stream, err := up.OpenVia(ctx, dest, decision.Action == routing.ActionEgress)
	if err != nil {
		h.log.Debug("поток не открылся", "target", dest, "err", err)
		return
	}
	defer stream.Close()

	// На учёт: переключение галки закрывает открытые потоки, иначе браузер продолжит
	// переиспользовать прежние соединения и покажет человеку старый маршрут.
	id := h.control.track(pair{local: conn, remote: stream})
	defer h.control.untrack(id)

	h.state.Exited(stream.ViaEgress())
	h.log.Debug("соединение пошло", "target", dest, "через_выход", stream.ViaEgress(),
		"by", decision.String())
	splice(conn, stream, h.state)
}

// HandleUDP обслуживает пакетные соединения.
//
// Служба имён разбирается на месте: она и нужна, чтобы у потоков появились имена. Прочий UDP
// уходит на узел датаграммами по RFC 9298 — тем же соединением и по тем же правилам, что и
// потоки. Без этого приложение, говорящее по QUIC, оказалось бы не там, где остальной его
// трафик, и заметить это можно было бы только по чужому адресу на сайте проверки.
func (h tunHandler) HandleUDP(ctx context.Context, conn io.ReadWriteCloser, target netip.AddrPort) {
	if h.dns != nil && dnsproxy.IsDNS(target) {
		// Про отказы при остановке молчим: стек закрывается, и все висевшие запросы падают
		// разом. Полсотни одинаковых строк в журнале про снятый туннель — не диагностика, а
		// помеха тому, кто ищет в нём настоящую причину.
		if err := h.dns.ServePacket(ctx, conn); err != nil && ctx.Err() == nil {
			h.log.Debug("служба имён завершилась ошибкой", "err", err)
		}
		return
	}

	name, isFake, decision, ok := h.resolve(ctx, target, true)
	if !ok || decision.Action == routing.ActionBlock {
		h.log.Debug("датаграммы отклонены", "target", describe(name, target), "by", decision.String())
		return
	}

	dest := target.String()
	if isFake {
		dest = net.JoinHostPort(name, strconv.Itoa(int(target.Port())))
	}

	up, err := h.link.Conn(ctx)
	if err != nil {
		h.log.Debug("связи с сетью нет", "target", dest, "err", err)
		return
	}
	packets, err := up.OpenUDP(ctx, dest, decision.Action == routing.ActionEgress)
	if err != nil {
		h.log.Debug("датаграммы не пошли", "target", dest, "err", err)
		return
	}
	defer packets.Close()

	id := h.control.track(pair{local: conn, remote: packets})
	defer h.control.untrack(id)

	h.log.Debug("датаграммы пошли", "target", dest, "by", decision.String())
	splicePackets(conn, packets, h.state)
}

// splicePackets гоняет датаграммы в обе стороны, пока одна из сторон не кончится.
//
// io.Copy здесь не годится: он вправе склеить два чтения в одну запись, а для UDP это уже
// другое сообщение.
func splicePackets(local, remote io.ReadWriteCloser, state *State) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyPackets(local, remote, state.addReceived)
		local.Close()
	}()
	copyPackets(remote, local, state.addSent)
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

// maxDatagram ограничивает читаемый пакет. Больше в датаграмму QUIC всё равно не влезет.
const maxDatagram = 1500

// describe показывает поток так, как его понял бы человек.
func describe(name string, target netip.AddrPort) string {
	if name == "" {
		return target.String()
	}
	return name + ":" + strconv.Itoa(int(target.Port()))
}

// blockedNames отвечает службе имён, запрещено ли имя правилами.
type blockedNames struct{ engine *routing.Engine }

func (b blockedNames) Blocked(name string) bool {
	return b.engine.Decide(routing.Flow{Domain: name}).Action == routing.ActionBlock
}

// tunOpener открывает потоки для службы имён — ей нужен путь к настоящему резолверу.
type tunOpener struct {
	link    *link.Link
	viaExit bool
}

func (o tunOpener) Open(ctx context.Context, target string) (io.ReadWriteCloser, error) {
	conn, err := o.link.Conn(ctx)
	if err != nil {
		return nil, err
	}
	return conn.OpenVia(ctx, target, o.viaExit)
}

// splice гоняет байты в обе стороны, пока одна из них не кончится.
//
// Считает по ходу дела, а не по завершении. Разница не косметическая: замер скорости и
// загрузка файла держат поток открытым всё время работы, и счёт «в конце» показывал бы ноль
// ровно тогда, когда человек смотрит на экран, а потом дёргался бы разом.
func splice(a io.ReadWriteCloser, b io.ReadWriter, state *State) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(counter{w: a, add: state.addReceived}, b)
	}()
	_, _ = io.Copy(counter{w: b, add: state.addSent}, a)
	a.Close()
	<-done
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

// runTunnel поднимает туннель и держит его, пока жив контекст.
func runTunnel(
	ctx context.Context,
	o Options,
	net *network,
	conn *link.Link,
	engine *routing.Engine,
	fd *fdGuard,
	log *slog.Logger,
) error {
	addrs, err := parsePrefixes(o.TunAddrs)
	if err != nil {
		return err
	}

	pool, err := fakeip.New(o.FakeRange, 0)
	if err != nil {
		return err
	}

	// Запросы к настоящему резолверу идут туда же, куда пошёл бы трафик к нему самому:
	// его адрес — обычная цель, и правила решают его судьбу наравне с прочими.
	upstreamVia := engine.Decide(flowOf(o.DNSUpstream)).Action == routing.ActionEgress

	dns := &dnsproxy.Server{
		Pool:     pool,
		Upstream: o.DNSUpstream,
		Open:     tunOpener{link: conn, viaExit: upstreamVia},
		Rules:    blockedNames{engine: engine},
		KeepDNS:  o.KeepDNS,
		Log:      log,
	}

	// Дескриптор переходит к туннелю: с этой минуты сторож в него не лезет.
	//
	// Именно до вызова, а не после удачного: при отказе внутри Open дескриптор может быть уже
	// закрыт (Open закрывает устройство, если не собрался стек), а может и нет — снаружи это
	// не различить. Закрыть его вторым было бы хуже утечки: двойное закрытие на Android ловит
	// fdsan и убивает процесс целиком.
	fd.taken()

	t, err := tunnel.Open(tunnel.Config{
		Name:  o.TunName,
		FD:    o.TunFD,
		MTU:   o.TunMTU,
		Addrs: addrs,
		Handler: tunHandler{
			link:    conn,
			engine:  engine,
			pool:    pool,
			dns:     dns,
			state:   o.State,
			control: o.Control,
			keepDNS: o.KeepDNS,
			log:     log,
		},
		Log: log,
	})
	if err != nil {
		return err
	}
	defer t.Close()

	// Маршруты расставляем сами, только если сами и создали интерфейс. Когда дескриптор
	// пришёл готовым (Android), всё это уже сделала система по запросу приложения, и лезть
	// туда нельзя: прав нет, а попытка кончилась бы отказом на ровном месте.
	var except []netip.Addr
	if o.TunFD == 0 {
		// Исключения обязаны встать до маршрута по умолчанию: иначе соединение с узлом уйдёт
		// в туннель, который сам через это соединение и работает. Исключаются **все** входные
		// узлы сети, а не только текущий: после обрыва гонка пойдёт заново, и завёрнутый в
		// туннель узел окажется недостижим ровно тогда, когда он нужнее всего.
		var err error
		except, err = exceptions(net.targets)
		if err != nil {
			return err
		}
		// Прочие адреса мимо туннеля. Управляющее соединение — самый частый случай:
		// заворачивая весь трафик на удалённой машине, легко отрезать себя от неё же.
		extra, err := parseAddrs(o.TunExcept)
		if err != nil {
			return err
		}
		except = append(except, extra...)

		if err := t.Configure(except, o.TunDefault); err != nil {
			return err
		}
		defer t.Deconfigure(except)

		// Пакеты на подменные адреса должны доходить до туннеля, иначе имя, которое мы только
		// что выдали, никуда не приведёт.
		if err := t.AddRoute(pool.Prefix()); err != nil {
			return err
		}
	}

	log.Info("туннель поднят", "iface", t.Name(), "mtu", t.MTU(),
		"addrs", o.TunAddrs, "default_route", o.TunDefault, "except", len(except),
		"fake_range", pool.Prefix().String(),
		"resolver", pool.ServiceAddr().String(), "upstream", o.DNSUpstream)

	// Страховка: туннель, через который ничего не ходит, хуже отсутствия туннеля — особенно
	// на машине, до которой добираются через него же. Не подтвердилась связь за отведённое
	// время — снимаем маршруты и выходим, вместо того чтобы оставить систему без сети.
	guard, cancelGuard := context.WithCancel(ctx)
	defer cancelGuard()
	go func() {
		if o.TunGuard <= 0 {
			return
		}
		select {
		case <-guard.Done():
			return
		case <-time.After(time.Duration(o.TunGuard) * time.Second):
		}
		if err := probe(ctx, conn); err != nil {
			log.Error("через туннель не ходит трафик, снимаю маршруты", "err", err)
			t.Deconfigure(except)
			t.Close()
			return
		}
		log.Info("связь через туннель подтверждена")
	}()

	return t.Run(ctx)
}

// probe проверяет, что через узел вообще открываются потоки.
func probe(ctx context.Context, l *link.Link) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	conn, err := l.Conn(ctx)
	if err != nil {
		return err
	}
	stream, err := conn.OpenVia(ctx, "1.1.1.1:443", false)
	if err != nil {
		return err
	}
	return stream.Close()
}

func parseAddrs(list string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("адрес-исключение %q: %w", s, err)
		}
		out = append(out, addr)
	}
	return out, nil
}

func parsePrefixes(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("адрес интерфейса %q: %w", s, err)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("не задан ни один адрес интерфейса")
	}
	return out, nil
}
