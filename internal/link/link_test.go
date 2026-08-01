package link

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/node"
	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/quicx"
	quic "github.com/quic-go/quic-go"
)

type directory map[string]oplog.PublicKey

func (d directory) PublicKey(role hello.Role, id string) (oplog.PublicKey, bool) {
	k, ok := d[role.String()+"/"+id]
	return k, ok
}

// testNode — узел, который можно уронить и поднять на том же адресе.
type testNode struct {
	addr    string
	key     *oplog.MemorySigner
	tls     *tls.Config
	pool    *x509.CertPool
	dir     directory
	stop    func()
	udpAddr *net.UDPAddr
}

func newTestNode(t *testing.T, clientPub oplog.PublicKey) *testNode {
	t.Helper()
	key, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("ключ узла: %v", err)
	}
	tlsConf, pool := testTLS(t)

	n := &testNode{
		key:  key,
		tls:  tlsConf,
		pool: pool,
		dir:  directory{"client/vasya": clientPub},
	}
	n.start(t)
	t.Cleanup(func() { n.kill() })
	return n
}

// start поднимает узел. Второй вызов возвращает его на тот же порт — так проверяется,
// что клиент нашёл дорогу назад сам.
func (n *testNode) start(t *testing.T) {
	t.Helper()
	if n.udpAddr == nil {
		n.udpAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	}

	udp, err := net.ListenUDP("udp", n.udpAddr)
	if err != nil {
		t.Fatalf("сокет: %v", err)
	}
	n.udpAddr = udp.LocalAddr().(*net.UDPAddr)
	n.addr = udp.LocalAddr().String()

	srv, err := node.New(node.Config{
		TLS:       n.tls,
		Identity:  hello.Identity{Role: hello.RoleNode, ID: "warsaw", Signer: n.key},
		Directory: n.dir,
		Control: func(ctx context.Context, peer *hello.Peer, stream io.ReadWriter) error {
			<-ctx.Done()
			return ctx.Err()
		},
		Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("сборка узла: %v", err)
	}

	tr := &quic.Transport{Conn: udp}
	serverTLS := n.tls.Clone()
	serverTLS.NextProtos = []string{quicx.ALPN}
	ln, err := tr.ListenEarly(serverTLS, quicx.ClientConfig(0))
	if err != nil {
		t.Fatalf("слушатель: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()

	n.stop = func() {
		srv.Close()
		ln.Close()
		tr.Close()
		udp.Close()
	}
}

func (n *testNode) kill() {
	if n.stop != nil {
		n.stop()
		n.stop = nil
	}
}

func (n *testNode) target() node.Target {
	return node.Target{
		ID:        "warsaw",
		Domain:    "qdiver.test",
		Endpoints: []string{n.addr},
		PublicKey: oplog.PublicKey(n.key.Public()),
	}
}

// Главное свойство связи: узел умер и вернулся — клиент нашёл дорогу сам, без вмешательства.
func TestLinkRecoversAfterNodeDies(t *testing.T) {
	clientKey, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("ключ клиента: %v", err)
	}
	n := newTestNode(t, oplog.PublicKey(clientKey.Public()))

	l, err := New(Config{
		Targets: []node.Target{n.target()},
		TLS:     &tls.Config{RootCAs: n.pool},
		Self:    hello.Identity{Role: hello.RoleClient, ID: "vasya", Signer: clientKey},
		Log:     slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("сборка связи: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	go func() { _ = l.Run(ctx) }()

	first, err := waitConn(l, 15*time.Second)
	if err != nil {
		t.Fatalf("первое соединение: %v", err)
	}
	if first.Peer().ID != "warsaw" {
		t.Fatalf("опознан не тот узел: %+v", first.Peer())
	}

	// Узел уходит. Соединение обязано умереть, а связь — заметить это.
	n.kill()
	if !waitDead(first, 20*time.Second) {
		t.Fatal("соединение не заметило смерти узла")
	}

	// Узел возвращается на тот же адрес.
	n.start(t)

	second, err := waitNewConn(l, first, 25*time.Second)
	if err != nil {
		t.Fatalf("связь не восстановилась: %v", err)
	}
	if second.Peer().ID != "warsaw" {
		t.Fatalf("после возврата опознан не тот узел: %+v", second.Peer())
	}
}

// Пока связи нет, потребитель обязан ждать её, а не получать отказ: для человека это разница
// между «грузится дольше обычного» и «нет интернета».
func TestConnWaitsInsteadOfFailing(t *testing.T) {
	clientKey, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	n := newTestNode(t, oplog.PublicKey(clientKey.Public()))

	l, err := New(Config{
		Targets: []node.Target{n.target()},
		TLS:     &tls.Config{RootCAs: n.pool},
		Self:    hello.Identity{Role: hello.RoleClient, ID: "vasya", Signer: clientKey},
		Log:     slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("сборка связи: %v", err)
	}

	// Спрашиваем ещё до запуска: вызов обязан ждать, а не вернуть ошибку.
	asked := make(chan error, 1)
	go func() {
		_, err := l.Conn(context.Background())
		asked <- err
	}()

	select {
	case err := <-asked:
		t.Fatalf("Conn вернулся до появления связи: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() { _ = l.Run(ctx) }()

	select {
	case err := <-asked:
		if err != nil {
			t.Fatalf("Conn отдал ошибку вместо соединения: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Conn так и не дождался связи")
	}
}

// Ожидание обязано слушаться контекста, иначе клиент не выключить.
func TestConnRespectsContext(t *testing.T) {
	clientKey, _ := oplog.GenerateSigner()
	l, err := New(Config{
		Targets: []node.Target{{ID: "x", Domain: "qdiver.test", Endpoints: []string{"127.0.0.1:1"}}},
		Self:    hello.Identity{Role: hello.RoleClient, ID: "vasya", Signer: clientKey},
		Log:     slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("сборка связи: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := l.Conn(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ждали истечения срока, получили %v", err)
	}
}

func TestLinkWithoutTargets(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, node.ErrNoTargets) {
		t.Fatalf("ждали ErrNoTargets, получили %v", err)
	}
}

func waitConn(l *Link, d time.Duration) (*node.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return l.Conn(ctx)
}

// waitNewConn ждёт соединение, отличное от прежнего.
func waitNewConn(l *Link, old *node.Conn, d time.Duration) (*node.Conn, error) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Until(deadline))
		conn, err := l.Conn(ctx)
		cancel()
		if err != nil {
			return nil, err
		}
		if conn != old {
			return conn, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, errors.New("новое соединение не появилось")
}

func waitDead(conn *node.Conn, d time.Duration) bool {
	select {
	case <-conn.QUIC().Context().Done():
		return true
	case <-time.After(d):
		return false
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
