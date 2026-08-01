package node

import (
	"context"
	"errors"
	"net"
	"time"
)

// Поток как обычное сетевое соединение.
//
// Нужно затем, что через сеть ходит не только пользовательский трафик: клиенту надо качать
// базы правил, а это обычный HTTP. Проще один раз обернуть поток в net.Conn и отдать его
// стандартному http.Transport, чем городить свой загрузчик.

// streamConn выдаёт поток за net.Conn.
type streamConn struct {
	stream *Stream
	local  net.Addr
	remote net.Addr
}

// tunnelAddr — адрес, которого нет. Поток идёт внутри QUIC-соединения, и настоящих
// сокетов у него на этом конце не существует.
type tunnelAddr struct{ name string }

func (a tunnelAddr) Network() string { return "qdiver" }
func (a tunnelAddr) String() string  { return a.name }

func (c *streamConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }
func (c *streamConn) Close() error                { return c.stream.Close() }
func (c *streamConn) LocalAddr() net.Addr         { return c.local }
func (c *streamConn) RemoteAddr() net.Addr        { return c.remote }

// Сроки поток не поддерживает: время жизни ему задаёт контекст запроса, а http.Transport
// умеет и без дедлайнов. Возвращать ошибку нельзя — Transport счёл бы соединение негодным.
func (c *streamConn) SetDeadline(time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

// DialContext открывает поток и выдаёт его за обычное соединение.
//
// viaExit решает, выпускать ли трафик через выходной узел, — то же самое, что и для
// пользовательских потоков.
func (c *Conn) DialContext(ctx context.Context, network, addr string, viaExit bool) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errors.New("node: через узел ходит только TCP")
	}

	stream, err := c.OpenVia(ctx, addr, viaExit)
	if err != nil {
		return nil, err
	}
	return &streamConn{
		stream: stream,
		local:  tunnelAddr{name: "client"},
		remote: tunnelAddr{name: addr},
	}, nil
}
