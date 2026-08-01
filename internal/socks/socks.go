// Package socks — локальный вход SOCKS5 (RFC 1928).
//
// Это не замена туннелю и не костыль вместо него. Отдельный вход нужен по двум причинам:
// им проверяется вся цепочка — правила, выбор выхода, сам выход — без единого пакета через
// TUN; и он остаётся полезным в готовом клиенте тем, кто хочет пустить через сеть одно
// приложение, а не всю систему.
//
// Чего на нём не проверить: перехвата DNS, подменных адресов и мгновенного RST. Всё это
// живёт на уровне пакетов и появится вместе с туннелем.
package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/jaywehosl/quic-diver/internal/procmatch"
)

const (
	version5 = 0x05

	authNone         = 0x00
	authNoAcceptable = 0xff

	cmdConnect = 0x01

	addrIPv4   = 0x01
	addrDomain = 0x03
	addrIPv6   = 0x04

	replyOK              = 0x00
	replyGeneralFailure  = 0x01
	replyNotAllowed      = 0x02
	replyHostUnreachable = 0x04
	replyCmdNotSupported = 0x07
)

// handshakeTimeout ограничивает переговоры: подключиться к локальному порту может кто угодно,
// в том числе неудачно, и висеть из-за этого клиент не должен.
const handshakeTimeout = 10 * time.Second

// Source — что известно о том, кто просит соединение.
type Source struct {
	// Process — имя процесса, если его удалось определить. Пусто, когда не удалось: это
	// обычное дело, а не поломка, и правило `process:` тогда просто не сработает.
	Process string
}

// Opener открывает поток до адреса. За ним стоит соединение с узлом.
type Opener interface {
	Open(ctx context.Context, target string, from Source) (io.ReadWriteCloser, error)
}

// Server — локальный вход.
type Server struct {
	// Addr — где слушать, обычно "127.0.0.1:1080".
	Addr string
	// Open — чем открывать потоки.
	Open Opener
	// Finder определяет процесс по концам соединения. Пустой означает, что правила по
	// процессам работать не будут.
	Finder procmatch.Finder
	// Log — куда писать.
	Log *slog.Logger
}

// ListenAndServe поднимает вход.
//
// Слушать наружу нельзя: SOCKS5 без пароля, открытый в сеть, — это открытый прокси, которым
// немедленно начнут пользоваться посторонние. Адрес проверяется, а не оставляется на совесть
// того, кто правит конфиг.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if err := checkLocal(s.Addr); err != nil {
		return err
	}
	if s.Log == nil {
		s.Log = slog.Default()
	}

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("socks: слушатель: %w", err)
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	s.Log.Info("вход SOCKS5 поднят", "addr", ln.Addr().String())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("socks: приём соединения: %w", err)
		}
		go s.handle(ctx, conn)
	}
}

func checkLocal(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("socks: адрес %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("socks: %q — вход обязан слушать только петлю, иначе это открытый прокси", addr)
	}
	return nil
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	target, err := negotiate(conn)
	if err != nil {
		s.Log.Debug("переговоры не вышли", "from", conn.RemoteAddr().String(), "err", err)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	stream, err := s.Open.Open(ctx, target, Source{Process: s.processOf(conn)})
	if err != nil {
		s.Log.Warn("поток не открылся", "target", target, "err", err)
		_ = reply(conn, replyHostUnreachable)
		return
	}
	defer stream.Close()

	if err := reply(conn, replyOK); err != nil {
		return
	}

	s.Log.Debug("поток пошёл", "target", target)
	splice(conn, stream)
}

// processOf выясняет, какой процесс пришёл за соединением.
//
// Концы берутся наоборот: то, что для нас удалённый адрес, для процесса — свой. Не найдётся
// — ничего страшного: правило `process:` не сработает, остальные отработают как обычно.
func (s *Server) processOf(conn net.Conn) string {
	if s.Finder == nil {
		return ""
	}
	local, ok1 := conn.RemoteAddr().(*net.TCPAddr)
	remote, ok2 := conn.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return ""
	}

	name, err := s.Finder.Lookup(local.AddrPort(), remote.AddrPort())
	if err != nil {
		s.Log.Debug("процесс не определён", "from", conn.RemoteAddr().String(), "err", err)
		return ""
	}
	return name
}

// negotiate проводит переговоры SOCKS5 и возвращает запрошенный адрес.
func negotiate(conn net.Conn) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", err
	}
	if head[0] != version5 {
		return "", fmt.Errorf("socks: версия %d не поддерживается", head[0])
	}

	methods := make([]byte, head[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	// Пароля нет и быть не должно: вход слушает только петлю, а пароль в конфиге у самого
	// себя защищает ровно ни от чего.
	if !contains(methods, authNone) {
		_, _ = conn.Write([]byte{version5, authNoAcceptable})
		return "", errors.New("socks: клиент требует проверки, которой у нас нет")
	}
	if _, err := conn.Write([]byte{version5, authNone}); err != nil {
		return "", err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return "", err
	}
	if req[0] != version5 {
		return "", fmt.Errorf("socks: версия запроса %d", req[0])
	}
	if req[1] != cmdConnect {
		_ = reply(conn, replyCmdNotSupported)
		return "", fmt.Errorf("socks: команда %d не поддерживается", req[1])
	}

	var host string
	switch req[3] {
	case addrIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case addrIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case addrDomain:
		n := make([]byte, 1)
		if _, err := io.ReadFull(conn, n); err != nil {
			return "", err
		}
		b := make([]byte, n[0])
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		_ = reply(conn, replyNotAllowed)
		return "", fmt.Errorf("socks: вид адреса %d", req[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// reply отвечает клиенту.
//
// Адрес в ответе нулевой намеренно: настоящий сообщил бы приложению, каким узлом мы вышли,
// а знать это ему незачем.
func reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{version5, code, 0x00, addrIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func splice(local net.Conn, remote io.ReadWriteCloser) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(local, remote)
		if cw, ok := local.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	_, _ = io.Copy(remote, local)
	remote.Close()
	<-done
}

func contains(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}
