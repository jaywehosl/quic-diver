package node

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/quic-go/quic-go"

	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/quicx"
)

// fakeImporter — журнал, который умеет только принимать.
type fakeImporter struct {
	genesis oplog.Fingerprint
	err     error
	got     []byte
}

func (f *fakeImporter) Genesis() oplog.Fingerprint { return f.genesis }

func (f *fakeImporter) Import(r io.Reader) (int, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	f.got = b
	if f.err != nil {
		return 0, f.err
	}
	f.genesis = oplog.Fingerprint{1}
	return 1, nil
}

// newImportHarness поднимает узел, умеющий принимать первый залив.
func newImportHarness(t *testing.T, imp Importer) *harness {
	t.Helper()

	nodeKey, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("ключ узла: %v", err)
	}
	tlsConf, pool := testTLS(t)
	h := &harness{pool: pool, nodeKey: nodeKey, control: make(chan *hello.Peer, 1)}

	n, err := New(Config{
		TLS:       tlsConf,
		Identity:  hello.Identity{Role: hello.RoleNode, ID: "fresh", Signer: nodeKey},
		Directory: directory{},
		Import:    imp,
		Control: func(ctx context.Context, peer *hello.Peer, stream io.ReadWriter) error {
			return nil
		},
		Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("сборка узла: %v", err)
	}
	h.node = n

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("сокет: %v", err)
	}
	tr := &quic.Transport{Conn: udp}
	serverTLS := tlsConf.Clone()
	serverTLS.NextProtos = []string{quicx.ALPN}
	ln, err := tr.ListenEarly(serverTLS, quicx.ClientConfig(0))
	if err != nil {
		t.Fatalf("слушатель: %v", err)
	}
	h.addr = udp.LocalAddr().String()

	go func() { _ = n.Serve(ln) }()
	t.Cleanup(func() {
		n.Close()
		ln.Close()
		tr.Close()
		udp.Close()
	})
	return h
}

// Пустой узел принимает журнал от кого угодно — опознать пришедшего ему нечем.
func TestEmptyNodeTakesTheFirstLog(t *testing.T) {
	imp := &fakeImporter{}
	h := newImportHarness(t, imp)
	cl, done := h.client(t)
	defer done()

	resp, err := cl.Post(h.url(BootstrapPath), "application/octet-stream", strings.NewReader("журнал"))
	if err != nil {
		t.Fatalf("залив: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("код %d, тело: %s", resp.StatusCode, body)
	}
	if string(imp.got) != "журнал" {
		t.Fatalf("журнал доехал не целиком: %q", imp.got)
	}
}

// Как только журнал принят, путь закрывается: узел знает владельцев и разговаривает только с
// теми, кто предъявил подпись.
func TestFilledNodeHidesBootstrap(t *testing.T) {
	imp := &fakeImporter{genesis: oplog.Fingerprint{7}}
	h := newImportHarness(t, imp)
	sameAsStranger(t, h, "журнал")
	if imp.got != nil {
		t.Fatal("узел с журналом всё-таки прочитал чужой залив")
	}
}

// Чужой журнал — та же заглушка. Разница в ответе выдала бы, что путь что-то значит.
func TestForeignLogGetsTheDecoy(t *testing.T) {
	imp := &fakeImporter{err: errors.New("журнал принадлежит другой сети")}
	h := newImportHarness(t, imp)
	sameAsStranger(t, h, "чужое")
	if !imp.Genesis().IsZero() {
		t.Fatal("чужой журнал осел в узле")
	}
}

// sameAsStranger проверяет, что залив отвечает ровно тем же, чем любой несуществующий путь.
//
// Сравнивается ответ, а не текст заглушки: разница в коде или теле выдала бы, что этот адрес
// вообще что-то значит, — а это и есть то, по чему узел находят.
func sameAsStranger(t *testing.T, h *harness, payload string) {
	t.Helper()
	cl, done := h.client(t)
	defer done()

	mine, err := cl.Post(h.url(BootstrapPath), "application/octet-stream", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("залив: %v", err)
	}
	defer mine.Body.Close()
	mineBody, _ := io.ReadAll(mine.Body)

	other, err := cl.Post(h.url("/какая-то/страница"), "application/octet-stream", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("запрос на обычный путь: %v", err)
	}
	defer other.Body.Close()
	otherBody, _ := io.ReadAll(other.Body)

	if mine.StatusCode != other.StatusCode {
		t.Fatalf("залив отвечает %d, обычный путь %d", mine.StatusCode, other.StatusCode)
	}
	if !bytes.Equal(mineBody, otherBody) {
		t.Fatalf("ответы различаются:\nзалив: %s\nобычный путь: %s", mineBody, otherBody)
	}
}
