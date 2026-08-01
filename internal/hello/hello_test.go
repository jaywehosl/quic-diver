package hello

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

func signer(t *testing.T) *oplog.MemorySigner {
	t.Helper()
	s, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}
	return s
}

// dir — простой справочник ключей для тестов.
type dir map[string]oplog.PublicKey

func (d dir) PublicKey(role Role, id string) (oplog.PublicKey, bool) {
	k, ok := d[role.String()+"/"+id]
	return k, ok
}

// pipe соединяет две стороны потоком без буфера — тем же, чем для приветствия является
// QUIC-стрим.
func pipe(t *testing.T) (io.ReadWriter, io.ReadWriter) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestExchangeSucceeds(t *testing.T) {
	node, client := signer(t), signer(t)
	binding := []byte("привязка к конкретной сессии, 32б")
	now := time.Now()

	d := dir{"client/vasya": oplog.PublicKey(client.Public())}
	serverSide, clientSide := pipe(t)

	type res struct {
		peer *Peer
		err  error
	}
	done := make(chan res, 1)
	go func() {
		p, err := Accept(serverSide, binding, Identity{Role: RoleNode, ID: "warsaw", Signer: node}, d, now)
		done <- res{p, err}
	}()

	peer, err := Initiate(clientSide, binding,
		Identity{Role: RoleClient, ID: "vasya", Signer: client},
		oplog.PublicKey(node.Public()), now)
	if err != nil {
		t.Fatalf("клиент: %v", err)
	}
	if peer.Role != RoleNode || peer.ID != "warsaw" {
		t.Fatalf("клиент опознал узел неверно: %+v", peer)
	}

	got := <-done
	if got.err != nil {
		t.Fatalf("узел: %v", got.err)
	}
	if got.peer.Role != RoleClient || got.peer.ID != "vasya" {
		t.Fatalf("узел опознал клиента неверно: %+v", got.peer)
	}
}

// Главное свойство: приветствие, снятое с одной сессии, бесполезно в другой.
func TestGreetingCannotBeReplayedIntoAnotherSession(t *testing.T) {
	client := signer(t)
	now := time.Now()

	h := &Hello{Version: Version, Role: RoleClient, ID: "vasya", Time: now}
	if err := h.Sign(client, []byte("привязка сессии номер один")); err != nil {
		t.Fatalf("подпись: %v", err)
	}

	err := h.Verify(oplog.PublicKey(client.Public()), []byte("привязка сессии номер два"), now)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("приветствие приняли в чужой сессии: %v", err)
	}
}

func TestUnknownPeerRejected(t *testing.T) {
	node, stranger := signer(t), signer(t)
	binding := []byte("привязка")
	now := time.Now()

	serverSide, clientSide := pipe(t)
	done := make(chan error, 1)
	go func() {
		_, err := Accept(serverSide, binding, Identity{Role: RoleNode, ID: "warsaw", Signer: node}, dir{}, now)
		done <- err
	}()

	go func() {
		_, _ = Initiate(clientSide, binding,
			Identity{Role: RoleClient, ID: "chuzhoy", Signer: stranger},
			oplog.PublicKey(node.Public()), now)
	}()

	if err := <-done; !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("незнакомец принят: %v", err)
	}
}

func TestForgedSignatureRejected(t *testing.T) {
	real, forger := signer(t), signer(t)
	binding := []byte("привязка")
	now := time.Now()

	h := &Hello{Version: Version, Role: RoleClient, ID: "vasya", Time: now}
	if err := h.Sign(forger, binding); err != nil {
		t.Fatalf("подпись: %v", err)
	}
	if err := h.Verify(oplog.PublicKey(real.Public()), binding, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("подделка принята: %v", err)
	}
}

func TestClockSkewRejected(t *testing.T) {
	s := signer(t)
	binding := []byte("привязка")
	now := time.Now()

	h := &Hello{Version: Version, Role: RoleNode, ID: "warsaw", Time: now.Add(-MaxClockSkew - time.Minute)}
	if err := h.Sign(s, binding); err != nil {
		t.Fatalf("подпись: %v", err)
	}
	if err := h.Verify(oplog.PublicKey(s.Public()), binding, now); !errors.Is(err, ErrClockSkew) {
		t.Fatalf("разъехавшиеся часы не пойманы: %v", err)
	}
}

func TestVersionMismatchRejected(t *testing.T) {
	s := signer(t)
	binding := []byte("привязка")
	now := time.Now()

	h := &Hello{Version: Version + 1, Role: RoleNode, ID: "warsaw", Time: now}
	if err := h.Sign(s, binding); err != nil {
		t.Fatalf("подпись: %v", err)
	}
	if err := h.Verify(oplog.PublicKey(s.Public()), binding, now); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("чужая версия принята: %v", err)
	}
}

func TestCodecRoundTrip(t *testing.T) {
	s := signer(t)
	binding := []byte("привязка")
	h := &Hello{Version: Version, Role: RoleAdmin, ID: "04c26c55f11de108", Time: time.Now()}
	if err := h.Sign(s, binding); err != nil {
		t.Fatalf("подпись: %v", err)
	}

	var buf bytes.Buffer
	if err := h.Encode(&buf); err != nil {
		t.Fatalf("кодирование: %v", err)
	}
	got, err := Decode(&buf)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if got.Role != h.Role || got.ID != h.ID || !got.Time.Equal(h.Time) {
		t.Fatalf("приветствие разъехалось: %+v против %+v", got, h)
	}
	if err := got.Verify(oplog.PublicKey(s.Public()), binding, h.Time); err != nil {
		t.Fatalf("подпись разобранного приветствия: %v", err)
	}
}

// Всё, что приходит в Decode, прислала ещё не опознанная сторона: длины нельзя брать на веру.
func TestDecodeRejectsHostileLengths(t *testing.T) {
	// Заявлен идентификатор длиной 60000 байт.
	hostile := []byte{0, 1, byte(RoleClient), 0xea, 0x60}
	if _, err := Decode(bytes.NewReader(hostile)); !errors.Is(err, ErrIDTooLong) {
		t.Fatalf("длина идентификатора взята на веру: %v", err)
	}

	// Обрыв посреди приветствия.
	if _, err := Decode(bytes.NewReader([]byte{0, 1})); !errors.Is(err, ErrTruncated) {
		t.Fatalf("обрыв не пойман: %v", err)
	}
}

func TestSignRejectsBadRole(t *testing.T) {
	s := signer(t)
	h := &Hello{Version: Version, Role: Role(9), ID: "x", Time: time.Now()}
	if err := h.Sign(s, []byte("привязка")); !errors.Is(err, ErrBadRole) {
		t.Fatalf("выдуманная роль принята: %v", err)
	}
}
