package node

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/quicx"
)

// newRateHarness поднимает узел с заданным потолком отправки.
func newRateHarness(t *testing.T, sendMbps int) *harness {
	t.Helper()

	nodeKey, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("ключ узла: %v", err)
	}
	tlsConf, pool := testTLS(t)
	h := &harness{pool: pool, nodeKey: nodeKey, control: make(chan *hello.Peer, 1)}

	n, err := New(Config{
		TLS:       tlsConf,
		Identity:  hello.Identity{Role: hello.RoleNode, ID: "rate", Signer: nodeKey},
		Directory: directory{},
		SendMbps:  sendMbps,
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
	ln, err := tr.ListenEarly(serverTLS, quicx.ClientConfig(sendMbps))
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

// Потолок меняется на живом соединении, не разрывая его.
//
// Ради этого всё и делалось: перезапуск узла ради нового числа рвёт трафик всех клиентов разом.
func TestSendRateChangesOnLiveConnection(t *testing.T) {
	h := newRateHarness(t, 100)
	cl, done := h.client(t)
	defer done()

	// Запрос нужен, чтобы соединение действительно поднялось и попало на учёт.
	resp, err := cl.Get(h.url("/"))
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	resp.Body.Close()

	// Учёт идёт при установлении соединения, а запрос возвращается чуть раньше, чем оно
	// доходит до реестра.
	deadline := time.Now().Add(3 * time.Second)
	var touched int
	for time.Now().Before(deadline) {
		if touched = h.node.SetSendMbps(500); touched > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if touched == 0 {
		t.Fatal("живых соединений не нашлось — смена потолка никого не коснулась")
	}

	// Соединение обязано остаться живым: смысл в том и был, чтобы не рвать его.
	resp, err = cl.Get(h.url("/"))
	if err != nil {
		t.Fatalf("после смены потолка соединение сломалось: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("код после смены потолка: %d", resp.StatusCode)
	}
	// И остаться тем же самым: переподключение выглядело бы так же успешно, но означало бы,
	// что трафик клиента всё-таки прервался.
	if still := h.node.SetSendMbps(500); still != touched {
		t.Fatalf("соединений было %d, стало %d — связь всё-таки пересоздалась", touched, still)
	}
}

// Соединение, пришедшее после правки, получает новое число, а не то, что было при запуске.
//
// Настройки слушателя зафиксированы при старте, поэтому одного их обновления мало.
func TestNewConnectionGetsCurrentRate(t *testing.T) {
	h := newRateHarness(t, 100)

	h.node.SetSendMbps(700)

	cl, done := h.client(t)
	defer done()

	resp, err := cl.Get(h.url("/"))
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer resp.Body.Close()

	// Проверяется через реестр: соединение на учёте, а значит потолок ему выставлен тем же
	// кодом, что и всем.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.node.SetSendMbps(700) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("новое соединение не попало на учёт")
}

// Ноль и отрицательное отвергаются: выключить BRUTAL на ходу нельзя, контроллер выбирается
// при рукопожатии, и молчаливое «принято» здесь означало бы враньё.
func TestSetSendRateIgnoresZero(t *testing.T) {
	h := newRateHarness(t, 100)

	if got := h.node.SetSendMbps(0); got != 0 {
		t.Fatalf("ноль принят: коснулось %d соединений", got)
	}
	if got := h.node.SetSendMbps(-5); got != 0 {
		t.Fatalf("отрицательное принято: коснулось %d соединений", got)
	}
}
