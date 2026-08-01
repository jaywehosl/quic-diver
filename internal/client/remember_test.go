package client

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/jaywehosl/quic-diver/internal/control"
	"github.com/jaywehosl/quic-diver/internal/node"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

func testKey(t *testing.T) oplog.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	return oplog.PublicKey(pub)
}

// Сеть, рассказавшая о себе, обязана пережить перезапуск клиента.
func TestRememberedNetworkSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	genesis := oplog.Fingerprint{9}

	one, two := testKey(t), testKey(t)
	snap := control.Snapshot{
		Network: "qdiver",
		Genesis: genesis,
		Egress:  true,
		Nodes: []control.SnapshotNode{
			{ID: "qdiver1", Domain: "one.example", Endpoints: []string{"203.0.113.1:443"}, PublicKey: one},
			{ID: "qdiver5", Domain: "five.example", Endpoints: []string{"203.0.113.5:443"}, PublicKey: two},
		},
	}

	memory := &networkMemory{dir: dir, genesis: genesis}
	memory.apply(snap, quiet())

	saved, ok := loadRemembered(dir, genesis, quiet())
	if !ok {
		t.Fatal("сеть не запомнилась")
	}
	if len(saved.Nodes) != 2 || !saved.Egress {
		t.Fatalf("запомнилось не то: %+v", saved)
	}
	// Ключ обязателен: без него к узлу не подключиться — приветствие не с чем сверять.
	if len(saved.targets()[0].PublicKey) != ed25519.PublicKeySize {
		t.Fatal("ключ узла потерялся при записи")
	}
	if saved.SavedUnix == 0 {
		t.Fatal("время записи не проставлено")
	}
}

// Файл от другой сети не берётся: две сети на одном устройстве — обычное дело.
func TestRememberedFromAnotherNetworkIgnored(t *testing.T) {
	dir := t.TempDir()
	mine, theirs := oplog.Fingerprint{1}, oplog.Fingerprint{2}

	memory := &networkMemory{dir: dir, genesis: theirs}
	memory.apply(control.Snapshot{
		Network: "чужая",
		Genesis: theirs,
		Nodes: []control.SnapshotNode{
			{ID: "чужой", Domain: "them.example", Endpoints: []string{"198.51.100.1:443"}, PublicKey: testKey(t)},
		},
	}, quiet())

	if _, ok := loadRemembered(dir, mine, quiet()); ok {
		t.Fatal("взяли сеть с чужим отпечатком")
	}
	if _, ok := loadRemembered(dir, theirs, quiet()); !ok {
		t.Fatal("своя сеть не читается — сверка отпечатка сломана в обе стороны")
	}
}

// Снапшот приходит дважды в минуту, а сеть меняется раз в месяц: файл переписывается только
// тогда, когда состав действительно другой.
func TestUnchangedSnapshotDoesNotRewrite(t *testing.T) {
	dir := t.TempDir()
	genesis := oplog.Fingerprint{3}
	key := testKey(t)

	snap := control.Snapshot{
		Network: "qdiver",
		Genesis: genesis,
		Nodes: []control.SnapshotNode{
			{ID: "qdiver1", Domain: "one.example", Endpoints: []string{"203.0.113.1:443"}, PublicKey: key},
		},
	}

	memory := &networkMemory{dir: dir, genesis: genesis}
	memory.apply(snap, quiet())
	first, _ := loadRemembered(dir, genesis, quiet())

	time.Sleep(1100 * time.Millisecond) // время записи хранится в секундах
	memory.apply(snap, quiet())
	second, _ := loadRemembered(dir, genesis, quiet())

	if first.SavedUnix != second.SavedUnix {
		t.Fatalf("файл переписан без изменений в сети: %d → %d", first.SavedUnix, second.SavedUnix)
	}
}

// Тот же снапшот с новым узлом обязан и записаться, и попасть в гонку.
func TestNewNodeReachesTheRace(t *testing.T) {
	dir := t.TempDir()
	genesis := oplog.Fingerprint{4}
	one, two := testKey(t), testKey(t)

	before := []node.Target{{ID: "qdiver1", Domain: "one.example", Endpoints: []string{"203.0.113.1:443"}, PublicKey: one}}
	memory := &networkMemory{dir: dir, genesis: genesis}
	memory.apply(control.Snapshot{
		Network: "qdiver", Genesis: genesis,
		Nodes: []control.SnapshotNode{
			{ID: before[0].ID, Domain: before[0].Domain, Endpoints: before[0].Endpoints, PublicKey: one},
		},
	}, quiet())

	memory.apply(control.Snapshot{
		Network: "qdiver", Genesis: genesis,
		Nodes: []control.SnapshotNode{
			{ID: "qdiver1", Domain: "one.example", Endpoints: []string{"203.0.113.1:443"}, PublicKey: one},
			{ID: "qdiver7", Domain: "seven.example", Endpoints: []string{"203.0.113.7:443"}, PublicKey: two},
		},
	}, quiet())

	saved, ok := loadRemembered(dir, genesis, quiet())
	if !ok || len(saved.Nodes) != 2 {
		t.Fatalf("новый узел не запомнился: %+v", saved)
	}
	if saved.Nodes[1].ID != "qdiver7" {
		t.Fatalf("запомнился не тот узел: %s", saved.Nodes[1].ID)
	}
}
