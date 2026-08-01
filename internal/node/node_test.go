package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/quicx"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// directory — простой справочник ключей.
type directory map[string]oplog.PublicKey

func (d directory) PublicKey(role hello.Role, id string) (oplog.PublicKey, bool) {
	k, ok := d[role.String()+"/"+id]
	return k, ok
}

type harness struct {
	node     *Node
	addr     string
	pool     *x509.CertPool
	nodeKey  *oplog.MemorySigner
	clientPK *oplog.MemorySigner
	control  chan *hello.Peer
}

func newHarness(t *testing.T, ctrl Control) *harness {
	t.Helper()
	return newNamedHarness(t, ctrl, "warsaw")
}

// newNamedHarness поднимает узел с заданным именем: в гонке участвуют несколько узлов сразу,
// и различать их приходится именно по имени.
func newNamedHarness(t *testing.T, ctrl Control, id string) *harness {
	t.Helper()

	nodeKey, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("ключ узла: %v", err)
	}
	clientKey, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("ключ клиента: %v", err)
	}

	tlsConf, pool := testTLS(t)
	h := &harness{
		pool:     pool,
		nodeKey:  nodeKey,
		clientPK: clientKey,
		control:  make(chan *hello.Peer, 1),
	}

	if ctrl == nil {
		ctrl = func(ctx context.Context, peer *hello.Peer, stream io.ReadWriter) error {
			h.control <- peer
			return nil
		}
	}

	n, err := New(Config{
		TLS:       tlsConf,
		Identity:  hello.Identity{Role: hello.RoleNode, ID: id, Signer: nodeKey},
		Directory: directory{"client/vasya": oplog.PublicKey(clientKey.Public())},
		Control:   ctrl,
		Log:       slog.New(slog.DiscardHandler),
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

// client собирает HTTP/3-клиента, доверяющего сертификату узла.
func (h *harness) client(t *testing.T) (*http.Client, func()) {
	t.Helper()
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: h.pool, ServerName: "qdiver.test"},
		QUICConfig:      quicx.ClientConfig(0),
		EnableDatagrams: true,
	}
	return &http.Client{Transport: tr}, func() { tr.Close() }
}

func (h *harness) url(path string) string { return "https://" + h.addr + path }

func TestStrangerGetsTheDecoy(t *testing.T) {
	h := newHarness(t, nil)
	cl, done := h.client(t)
	defer done()

	resp, err := cl.Get(h.url("/"))
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("код: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Under construction") {
		t.Fatalf("отдана не заглушка: %s", body)
	}
	if resp.Header.Get("Server") != "" {
		t.Fatal("HTTP/3 добавил заголовок Server")
	}
}

// Главное свойство узла: управляющий путь без приветствия неотличим от любого другого
// несуществующего адреса.
func TestControlPathLooksLikeAnyOtherPathToAStranger(t *testing.T) {
	h := newHarness(t, nil)
	cl, done := h.client(t)
	defer done()

	control, err := cl.Post(h.url(ControlPath), "application/octet-stream", strings.NewReader("не приветствие"))
	if err != nil {
		t.Fatalf("запрос на управляющий путь: %v", err)
	}
	defer control.Body.Close()
	controlBody, _ := io.ReadAll(control.Body)

	other, err := cl.Post(h.url("/какая-то/страница"), "application/octet-stream", strings.NewReader("не приветствие"))
	if err != nil {
		t.Fatalf("запрос на обычный путь: %v", err)
	}
	defer other.Body.Close()
	otherBody, _ := io.ReadAll(other.Body)

	if control.StatusCode != other.StatusCode {
		t.Fatalf("коды разошлись: %d на управляющем пути против %d на обычном",
			control.StatusCode, other.StatusCode)
	}
	if string(controlBody) != string(otherBody) {
		t.Fatalf("тела разошлись:\n%s\n---\n%s", controlBody, otherBody)
	}
}

func TestKnownClientGetsControlStream(t *testing.T) {
	const word = "привет"
	echo := func(ctx context.Context, peer *hello.Peer, stream io.ReadWriter) error {
		buf := make([]byte, len(word))
		if _, err := io.ReadFull(stream, buf); err != nil {
			return err
		}
		_, err := stream.Write(buf)
		return err
	}
	h := newHarness(t, echo)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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

	if conn.Peer().Role != hello.RoleNode || conn.Peer().ID != "warsaw" {
		t.Fatalf("узел опознан неверно: %+v", conn.Peer())
	}

	// Поток двусторонний: пишем и тут же читаем ответ.
	if _, err := conn.Stream().Write([]byte(word)); err != nil {
		t.Fatalf("запись: %v", err)
	}
	buf := make([]byte, len(word))
	if _, err := io.ReadFull(conn.Stream(), buf); err != nil {
		t.Fatalf("чтение: %v", err)
	}
	if string(buf) != word {
		t.Fatalf("эхо вернуло %q", buf)
	}
}

// Клиент проверяет узел так же, как узел клиента: подпись должна сойтись с тем ключом,
// которого мы ждём. Это не дублирует TLS — TLS опирается на публичную PKI, а тут её нет.
func TestClientRejectsNodeWithWrongKey(t *testing.T) {
	h := newHarness(t, nil)
	wrong, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err = Dial(ctx, h.addr,
		&tls.Config{RootCAs: h.pool, ServerName: "qdiver.test"},
		hello.Identity{Role: hello.RoleClient, ID: "vasya", Signer: h.clientPK},
		oplog.PublicKey(wrong.Public()),
		0,
	)
	if err == nil {
		t.Fatal("клиент принял узел с чужим ключом")
	}
}

// Незнакомый клиент не должен получить ни потока, ни намёка на причину отказа.
func TestUnknownClientIsTurnedAway(t *testing.T) {
	h := newHarness(t, nil)
	stranger, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err = Dial(ctx, h.addr,
		&tls.Config{RootCAs: h.pool, ServerName: "qdiver.test"},
		hello.Identity{Role: hello.RoleClient, ID: "chuzhoy", Signer: stranger},
		oplog.PublicKey(h.nodeKey.Public()),
		0,
	)
	if err == nil {
		t.Fatal("незнакомец получил управляющий поток")
	}
	select {
	case peer := <-h.control:
		t.Fatalf("обработчик всё-таки вызвали для %+v", peer)
	default:
	}
}

func testTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "qdiver.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"qdiver.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("сертификат: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		NextProtos:   []string{quicx.ALPN},
	}, pool
}
