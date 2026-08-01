package node

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

func (h *harness) target(id string) Target {
	return Target{
		ID:        id,
		Domain:    "qdiver.test",
		Endpoints: []string{h.addr},
		PublicKey: oplog.PublicKey(h.nodeKey.Public()),
	}
}

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// Гонка обязана вернуть соединение, пока жив хоть один узел из списка.
func TestRaceTakesWhoeverAnswers(t *testing.T) {
	live := newNamedHarness(t, holdOpen, "live")

	targets := []Target{
		// Мёртвый адрес: порт, на котором никого нет.
		{ID: "dead", Domain: "qdiver.test", Endpoints: []string{"127.0.0.1:1"},
			PublicKey: oplog.PublicKey(live.nodeKey.Public())},
		live.target("live"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := DialRace(ctx, targets, &tls.Config{RootCAs: live.pool},
		hello.Identity{Role: hello.RoleClient, ID: "vasya", Signer: live.clientPK}, 0, quiet())
	if err != nil {
		t.Fatalf("гонка: %v", err)
	}
	defer conn.Close()

	if conn.Peer().ID != "live" {
		t.Fatalf("опознан не тот узел: %+v", conn.Peer())
	}
}

// Узел, который нас не признаёт, гонку выиграть не должен: TLS он поднимет, а толку ноль.
// Ради этого гонка и ждёт приветствия, а не рукопожатия.
func TestRaceIgnoresNodeThatRefusesUs(t *testing.T) {
	friend := newNamedHarness(t, holdOpen, "friend")
	stranger := newNamedHarness(t, holdOpen, "stranger")
	// Чужак не знает нашего клиента вовсе.
	stranger.node.cfg.Directory = directory{}

	targets := []Target{
		{ID: "stranger", Domain: "qdiver.test", Endpoints: []string{stranger.addr},
			PublicKey: oplog.PublicKey(stranger.nodeKey.Public())},
		friend.target("friend"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := DialRace(ctx, targets, &tls.Config{RootCAs: friend.pool},
		hello.Identity{Role: hello.RoleClient, ID: "vasya", Signer: friend.clientPK}, 0, quiet())
	if err != nil {
		t.Fatalf("гонка: %v", err)
	}
	defer conn.Close()

	if conn.Peer().ID != "friend" {
		t.Fatalf("гонку выиграл %s — узел, который нас не признал", conn.Peer().ID)
	}
}

// Проигравший обязан получить закрытие, а не остаться висеть: иначе узел держит сессию,
// горутину и сокет до самого idle-таймаута.
func TestRaceClosesLosers(t *testing.T) {
	first := newNamedHarness(t, holdOpen, "first")
	second := newNamedHarness(t, holdOpen, "second")

	// Клиент один на оба узла — иначе один из них отказал бы и гонки не вышло.
	client := first.clientPK
	pub := oplog.PublicKey(client.Public())
	first.node.cfg.Directory = directory{"client/vasya": pub}
	second.node.cfg.Directory = directory{"client/vasya": pub}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := DialRace(ctx, []Target{first.target("first"), second.target("second")},
		&tls.Config{RootCAs: first.pool},
		hello.Identity{Role: hello.RoleClient, ID: "vasya", Signer: client}, 0, quiet())
	if err != nil {
		t.Fatalf("гонка: %v", err)
	}
	defer conn.Close()

	loser := second
	if conn.Peer().ID == "second" {
		loser = first
	}

	// Закрытие приходит явным пакетом, а не по таймауту, поэтому ждать долго не приходится.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if loser.node.sessions.count() == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("проигравший %s всё ещё держит %d сессий",
		loser.node.cfg.Identity.ID, loser.node.sessions.count())
}

func TestRaceWithoutTargets(t *testing.T) {
	_, err := DialRace(context.Background(), nil, &tls.Config{}, hello.Identity{}, 0, quiet())
	if !errors.Is(err, ErrNoTargets) {
		t.Fatalf("ждали ErrNoTargets, получили %v", err)
	}
}

// Все узлы мертвы — гонка обязана сказать об этом, а не ждать вечно.
func TestRaceWhenNobodyAnswers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := DialRace(ctx,
		[]Target{{ID: "dead", Domain: "qdiver.test", Endpoints: []string{"127.0.0.1:1", "127.0.0.1:2"}}},
		&tls.Config{}, hello.Identity{}, 0, quiet())
	if err == nil {
		t.Fatal("гонка к мёртвым адресам вернула соединение")
	}
}
