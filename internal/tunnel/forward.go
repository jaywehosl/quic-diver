package tunnel

import (
	"context"
	"net/netip"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// virtioOffset — место, которое надо оставить в начале каждого буфера.
//
// Не украшение: на Linux wireguard-go открывает устройство с IFF_VNET_HDR, и при записи
// сам отступает назад на длину заголовка virtio (десять байт). При нулевом отступе это
// смещение уходит в минус, и пакеты просто не доезжают — молча, без единой ошибки.
// Шестнадцать байт берём с запасом, ровно как это делает сам wireguard-go.
const virtioOffset = 16

// maxInFlight — сколько соединений могут одновременно ждать установления.
const maxInFlight = 2048

// newPayload оборачивает пакет в то, что понимает стек.
func newPayload(b []byte) buffer.Buffer {
	return buffer.MakeWithData(b)
}

// installForwarders вешает обработчики на TCP и UDP.
func (t *Tunnel) installForwarders() {
	tcpFwd := tcp.NewForwarder(t.stack, 0, maxInFlight, func(r *tcp.ForwarderRequest) {
		t.serveTCP(r)
	})
	t.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(t.stack, func(r *udp.ForwarderRequest) bool {
		t.serveUDP(r)
		return true
	})
	t.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
}

// serveTCP принимает соединение и отдаёт его обработчику.
//
// Соединение подтверждается только после того, как обработчик решил его судьбу. Это и есть
// та самая мгновенная блокировка: заблокированный адрес получает RST сразу, вместо того
// чтобы висеть до таймаута.
func (t *Tunnel) serveTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	target := endpointOf(id.LocalAddress, id.LocalPort)

	// Решение принимается до ответа на SYN: только так отказ доходит до приложения
	// сбросом, а не разрывом уже открытого соединения.
	if !t.cfg.Handler.Allow(target) {
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		// Отказ на этой стадии — обычная жизнь стека: клиент передумал, пакет пришёл
		// дважды. RST отправляем, чтобы приложение не ждало.
		t.log.Debug("стек не создал соединение", "target", target.String(), "err", err.String())
		r.Complete(true)
		return
	}
	r.Complete(false)

	// Задержка подтверждений вредна для интерактива: она копит по сорок миллисекунд на
	// каждом мелком обмене, а таких в вебе большинство.
	ep.SocketOptions().SetDelayOption(false)

	conn := gonet.NewTCPConn(&wq, ep)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		defer conn.Close()
		t.cfg.Handler.HandleTCP(ctx, conn, target)
	}()
}

// serveUDP принимает пакетное соединение.
//
// UDP нужен прежде всего для DNS: запрос на порт 53 заканчивается в клиенте, а имя разрешает
// узел. Остальной UDP поедет тем же путём, когда появится проксирование датаграмм.
func (t *Tunnel) serveUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	target := endpointOf(id.LocalAddress, id.LocalPort)

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return
	}

	conn := gonet.NewUDPConn(&wq, ep)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		defer conn.Close()
		t.cfg.Handler.HandleUDP(ctx, conn, target)
	}()
}

// endpointOf собирает адрес назначения из того, что видит стек.
func endpointOf(addr tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(addr.AsSlice())
	return netip.AddrPortFrom(ip.Unmap(), port)
}
