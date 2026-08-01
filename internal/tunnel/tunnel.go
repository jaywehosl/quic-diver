// Package tunnel поднимает TUN и терминирует на нём потоки.
//
// Из TUN приходят IP-пакеты, а сеть работает потоками: клиент просит узел открыть TCP до
// адреса. Между этими двумя мирами стоит стек в пространстве пользователя — netstack из
// gVisor. Он собирает пакеты в соединения, и дальше каждое соединение уходит своим потоком.
//
// # Почему терминация, а не проброс пакетов
//
// Решение 000 §3. Коротко: правила по доменам, мгновенный RST для заблокированного и выход в
// IPv6 с машины без IPv6 — всё это требует знания потока. При пробросе голых пакетов их
// пришлось бы добывать трансляцией заголовков, кодом, который ошибается тихо. Здесь же они
// получаются сами собой: соединение уже разобрано, адрес назначения известен, а наружу его
// открывает узел обычным сокетом.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	// nicID — единственная сетевая карта стека.
	nicID tcpip.NICID = 1

	// queueDepth — сколько пакетов ждут отправки в TUN.
	//
	// Очередь нужна, но короткая: длинная только копит задержку, не прибавляя пропускной
	// способности, — тот самый bufferbloat.
	queueDepth = 512

	// batchSize — сколько пакетов забирается из TUN за раз.
	batchSize = 128
)

// Handler решает судьбу принятого соединения.
type Handler interface {
	// Allow решает, принимать ли соединение вообще.
	//
	// Спрашивается до того, как стек ответит на SYN. Отказ здесь превращается в RST, и
	// приложение узнаёт правду сразу; отказ после установления выглядел бы как разрыв уже
	// открытого соединения — браузер в этом случае показывает не «сайт заблокирован», а
	// «соединение сброшено», и ждёт, и пробует снова.
	Allow(target netip.AddrPort) bool
	// HandleTCP получает установленное соединение и адрес, куда его просили направить.
	HandleTCP(ctx context.Context, conn io.ReadWriteCloser, target netip.AddrPort)
	// HandleUDP получает пакетное соединение и адрес назначения.
	HandleUDP(ctx context.Context, conn io.ReadWriteCloser, target netip.AddrPort)
}

// Config — что нужно туннелю.
type Config struct {
	// Name — имя интерфейса.
	Name string
	// MTU — размер пакета.
	//
	// Внутри туннеля едут байты потоков, а не IP-пакеты, поэтому бюджета на вложенные
	// заголовки закладывать не нужно: клиентский стек сегментирует по нашему MSS, а не по
	// тому, что осталось от чужого MTU.
	MTU int
	// Addrs — адреса, которые получает интерфейс.
	Addrs []netip.Prefix
	// FD — готовый дескриптор устройства.
	//
	// Так работает Android: интерфейс создаёт и настраивает система по запросу приложения
	// (VpnService), а нам достаётся уже открытый дескриптор. Создавать своё устройство там
	// нельзя и незачем — прав нет, да и маршруты система расставит сама.
	//
	// Ноль означает обычный путь: создать интерфейс самим по имени.
	FD int
	// Handler — что делать с принятыми соединениями.
	Handler Handler
	// Log — куда писать.
	Log *slog.Logger
}

// Tunnel — поднятый интерфейс со стеком.
type Tunnel struct {
	cfg    Config
	log    *slog.Logger
	dev    tun.Device
	ep     *channel.Endpoint
	stack  *stack.Stack
	name   string
	closed sync.Once
	done   chan struct{}
}

// Open поднимает интерфейс и стек над ним.
func Open(cfg Config) (*Tunnel, error) {
	if cfg.Handler == nil {
		return nil, errors.New("tunnel: не задан обработчик соединений")
	}
	if cfg.MTU <= 0 {
		cfg.MTU = 1500
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}

	dev, name, err := openDevice(cfg)
	if err != nil {
		return nil, err
	}

	t := &Tunnel{
		cfg:  cfg,
		log:  cfg.Log,
		dev:  dev,
		name: name,
		done: make(chan struct{}),
		ep:   channel.New(queueDepth, uint32(cfg.MTU), ""),
	}

	if err := t.buildStack(); err != nil {
		dev.Close()
		return nil, err
	}
	return t, nil
}

// Name возвращает имя поднятого интерфейса.
func (t *Tunnel) Name() string { return t.name }

// MTU возвращает размер пакета интерфейса.
func (t *Tunnel) MTU() int { return t.cfg.MTU }

func (t *Tunnel) buildStack() error {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	if err := s.CreateNIC(nicID, t.ep); err != nil {
		return fmt.Errorf("tunnel: создание интерфейса стека: %v", err)
	}

	// Пакеты приходят на любые адреса, а не только на наши: мы принимаем их за весь мир,
	// поэтому и слушаем всё подряд, и отвечаем от чужого имени.
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	for _, p := range t.cfg.Addrs {
		proto := ipv4.ProtocolNumber
		if p.Addr().Is6() {
			proto = ipv6.ProtocolNumber
		}
		addr := tcpip.ProtocolAddress{
			Protocol:          proto,
			AddressWithPrefix: tcpip.AddrFromSlice(p.Addr().AsSlice()).WithPrefix(),
		}
		if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
			return fmt.Errorf("tunnel: адрес %s: %v", p, err)
		}
	}

	t.stack = s
	t.installForwarders()
	return nil
}

// Run гоняет пакеты между интерфейсом и стеком, пока жив контекст.
func (t *Tunnel) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		t.fromDevice(ctx)
	}()
	go func() {
		defer wg.Done()
		t.toDevice(ctx)
	}()

	<-ctx.Done()
	t.Close()
	wg.Wait()
	return nil
}

// fromDevice забирает пакеты из интерфейса и отдаёт стеку.
func (t *Tunnel) fromDevice(ctx context.Context) {
	// Читаем батчами: на каждый пакет отдельный системный вызов — это заметная часть
	// процессорного времени при заметном трафике.
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, t.cfg.MTU+virtioOffset)
	}

	for {
		n, err := t.dev.Read(bufs, sizes, virtioOffset)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, tun.ErrTooManySegments) {
				t.log.Debug("чтение из интерфейса прекращено", "err", err)
			}
			return
		}
		for i := 0; i < n; i++ {
			packet := bufs[i][virtioOffset : virtioOffset+sizes[i]]
			if len(packet) == 0 {
				continue
			}

			proto := ipv4.ProtocolNumber
			if header.IPVersion(packet) == header.IPv6Version {
				proto = ipv6.ProtocolNumber
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: newPayload(packet),
			})
			t.ep.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}
}

// toDevice забирает пакеты у стека и пишет в интерфейс.
func (t *Tunnel) toDevice(ctx context.Context) {
	bufs := make([][]byte, 1)
	buf := make([]byte, t.cfg.MTU+virtioOffset)

	for {
		pkt := t.ep.ReadContext(ctx)
		if pkt == nil {
			return
		}

		view := pkt.ToView()
		n, err := view.Read(buf[virtioOffset:])
		view.Release()
		pkt.DecRef()
		if err != nil {
			continue
		}

		bufs[0] = buf[:virtioOffset+n]
		if _, err := t.dev.Write(bufs, virtioOffset); err != nil {
			if ctx.Err() == nil {
				t.log.Debug("запись в интерфейс прекращена", "err", err)
			}
			return
		}
	}
}

// Close закрывает интерфейс и стек.
func (t *Tunnel) Close() error {
	var err error
	t.closed.Do(func() {
		close(t.done)
		t.ep.Close()
		if t.stack != nil {
			t.stack.Close()
		}
		err = t.dev.Close()
	})
	return err
}
