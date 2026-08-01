package node

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Путь по RFC 9298 §3 должен пережить дорогу туда и обратно, включая адреса, у которых
// внутри есть двоеточия: сегментом пути они быть не должны.
func TestUDPPathSurvivesRoundTrip(t *testing.T) {
	for _, target := range []string{
		"1.2.3.4:53",
		"example.com:443",
		"[2001:db8::1]:443",
	} {
		path, err := udpPath(target)
		if err != nil {
			t.Fatalf("%s: сборка пути: %v", target, err)
		}
		u, err := parseRequestPath(path)
		if err != nil {
			t.Fatalf("%s: путь %q не разобрался как URL: %v", target, path, err)
		}
		got, err := parseUDPPath(u)
		if err != nil {
			t.Fatalf("%s: разбор пути %q: %v", target, path, err)
		}
		if got != target {
			t.Fatalf("путь %q вернул %q вместо %q", path, got, target)
		}
	}
}

func TestUDPPathRejectsRubbish(t *testing.T) {
	for _, path := range []string{
		"/",
		"/qd/v1/control",
		"/.well-known/masque/udp/",
		"/.well-known/masque/udp/example.com/",
		"/.well-known/masque/udp/example.com/443",       // без завершающей косой черты
		"/.well-known/masque/udp/example.com/443/more/", // лишний сегмент
		"/.well-known/masque/udp/example.com/https/",    // порт словом
		"/.well-known/masque/udp//443/",                 // пустое имя
	} {
		u, err := parseRequestPath(path)
		if err != nil {
			t.Fatalf("путь %q не разобрался как URL: %v", path, err)
		}
		if target, err := parseUDPPath(u); err == nil {
			t.Fatalf("путь %q принят как %q", path, target)
		}
	}
}

// Датаграммы должны доходить до внешнего сокета и возвращаться обратно, сохраняя границы
// сообщений: для UDP они и есть содержание.
func TestKnownClientGetsDatagrams(t *testing.T) {
	echo := newUDPEcho(t)
	h := newHarness(t, holdOpen)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := Dial(ctx, h.addr,
		&tls.Config{RootCAs: h.pool, ServerName: "qdiver.test"},
		hello.Identity{Role: hello.RoleClient, ID: "vasya", Signer: h.clientPK},
		oplog.PublicKey(h.nodeKey.Public()),
		0,
	)
	if err != nil {
		t.Fatalf("соединение: %v", err)
	}
	defer conn.Close()

	packets, err := conn.OpenUDP(ctx, echo, false)
	if err != nil {
		t.Fatalf("датаграммы не открылись: %v", err)
	}
	defer packets.Close()

	// Два разных по длине сообщения подряд: склеенные в одно они бы не сошлись.
	for _, word := range []string{"пинг", "и слово подлиннее"} {
		if _, err := packets.Write([]byte(word)); err != nil {
			t.Fatalf("отправка %q: %v", word, err)
		}
		buf := make([]byte, 1500)
		n, err := readWithDeadline(packets, buf, 10*time.Second)
		if err != nil {
			t.Fatalf("приём ответа на %q: %v", word, err)
		}
		if string(buf[:n]) != word {
			t.Fatalf("вернулось %q вместо %q", buf[:n], word)
		}
	}
}

// Расширенный CONNECT без приветствия должен выглядеть так же, как всё прочее: заглушкой.
func TestDatagramsRefusedWithoutGreeting(t *testing.T) {
	echo := newUDPEcho(t)
	h := newHarness(t, holdOpen)
	cl, done := h.client(t)
	defer done()

	path, err := udpPath(echo)
	if err != nil {
		t.Fatalf("сборка пути: %v", err)
	}
	req, err := http.NewRequest(http.MethodConnect, h.url(path), nil)
	if err != nil {
		t.Fatalf("сборка запроса: %v", err)
	}
	req.Proto = udpProtocol

	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("узел выпустил датаграммы без приветствия")
	}
	body, _ := io.ReadAll(resp.Body)

	// Отказ обязан выглядеть как ответ на любой другой адрес: разница в реакции и есть то,
	// что выдало бы узел.
	other, err := http.NewRequest(http.MethodConnect, h.url("/какая-то/страница"), nil)
	if err != nil {
		t.Fatalf("сборка запроса: %v", err)
	}
	other.Proto = udpProtocol
	otherResp, err := cl.Do(other)
	if err != nil {
		t.Fatalf("запрос на обычный путь: %v", err)
	}
	defer otherResp.Body.Close()
	otherBody, _ := io.ReadAll(otherResp.Body)

	if resp.StatusCode != otherResp.StatusCode {
		t.Fatalf("коды разошлись: %d на пути датаграмм против %d на обычном",
			resp.StatusCode, otherResp.StatusCode)
	}
	if string(body) != string(otherBody) {
		t.Fatalf("тела разошлись:\n%s\n---\n%s", body, otherBody)
	}
}

// parseRequestPath разбирает путь ровно так же, как это делает сам http3 на сервере.
func parseRequestPath(path string) (*url.URL, error) { return url.ParseRequestURI(path) }

// holdOpen держит управляющий поток открытым: сессия живёт ровно столько же, и без этого
// запрос датаграмм пришёл бы на узел, уже забывший собеседника.
func holdOpen(ctx context.Context, peer *hello.Peer, stream io.ReadWriter) error {
	<-ctx.Done()
	return ctx.Err()
}

// newUDPEcho поднимает сокет, возвращающий присланное обратно.
func newUDPEcho(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("эхо-сокет: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteToUDP(buf[:n], from); err != nil {
				return
			}
		}
	}()
	return conn.LocalAddr().String()
}

// readWithDeadline читает пакет, не давая тесту повиснуть навсегда.
func readWithDeadline(r io.Reader, buf []byte, d time.Duration) (int, error) {
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := r.Read(buf)
		done <- result{n, err}
	}()
	select {
	case res := <-done:
		return res.n, res.err
	case <-time.After(d):
		return 0, context.DeadlineExceeded
	}
}
