package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/store"
)

// openStore поднимает журнал с генезисом и одним узлом.
func openStore(t *testing.T) (*store.Store, *oplog.MemorySigner) {
	t.Helper()

	owner, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("ключ владельца: %v", err)
	}
	spare, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("запасной ключ: %v", err)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "oplog.db"), oplog.Fingerprint{})
	if err != nil {
		t.Fatalf("журнал: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	genesis := oplog.Genesis{
		Network: "qdiver",
		Owners: []oplog.AdminKey{
			{PublicKey: oplog.PublicKey(owner.Public()), Scope: oplog.ScopeOwner, Label: "основной"},
			{PublicKey: oplog.PublicKey(spare.Public()), Scope: oplog.ScopeOwner, Label: "запасной"},
		},
	}
	submit(t, st, owner, 1, oplog.KindGenesis, genesis)
	submit(t, st, owner, 2, oplog.KindNodeAdd, oplog.Node{
		ID:        "qdiver1",
		PublicKey: nodeKey(t),
		Roles:     []string{oplog.RoleIngress},
		Domain:    "qdiver1.example.com",
		Endpoints: []string{"192.0.2.1:443"},
	})
	return st, owner
}

func nodeKey(t *testing.T) oplog.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ключ узла: %v", err)
	}
	return oplog.PublicKey(pub)
}

func submit(t *testing.T, st *store.Store, signer *oplog.MemorySigner, counter uint64, kind oplog.Kind, body any) {
	t.Helper()
	op, err := oplog.NewOp(signer, kind, counter, time.Now().UTC(), body)
	if err != nil {
		t.Fatalf("подпись записи: %v", err)
	}
	if _, err := st.Append(op); err != nil {
		t.Fatalf("запись в журнал: %v", err)
	}
}

// Клиент получает снапшот сразу, не спрашивая.
func TestSnapshotArrivesWithoutAsking(t *testing.T) {
	st, owner := openStore(t)
	submit(t, st, owner, 3, oplog.KindSettingsSet, oplog.Settings{BrutalDownMbps: 200})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = ServeSnapshots(ctx, server, st, "vasya", nil) }()

	snap := readOne(t, client)
	if snap.Network != "qdiver" {
		t.Fatalf("сеть в снапшоте: %q", snap.Network)
	}
	if snap.Genesis != st.State().Genesis() {
		t.Fatal("отпечаток в снапшоте не тот")
	}
	if snap.Settings.BrutalDownMbps != 200 {
		t.Fatalf("параметры сети не доехали: %+v", snap.Settings)
	}
	if len(snap.Ingress()) != 1 {
		t.Fatalf("входные узлы не доехали: %+v", snap.Nodes)
	}
	if snap.HasEgress() {
		t.Fatal("выходных узлов нет, а снапшот утверждает обратное")
	}
}

// Правила маршрутизации клиенту не отдаются вовсе: они принадлежат человеку.
//
// ТЗ ст. 36 говорит «поддержка формата v2fly на клиенте. Выбрал geosite:… — отправил в
// blackhole» — выбирает человек, и список правил его. Раньше правила ехали снапшотом и
// затирали клиентские; это и было ошибкой.
func TestSnapshotCarriesNoRules(t *testing.T) {
	st, owner := openStore(t)
	// Домен нарочно не пересекается с именами узлов из openStore: иначе тест поймал бы сам
	// себя на подстроке и соврал.
	submit(t, st, owner, 3, oplog.KindRoutingSet, oplog.Routing{
		Rules: []oplog.Rule{{
			Match:   []string{"domain:zapreshcheno.invalid"},
			Action:  oplog.ActionBlock,
			Comment: "правило-маячок",
		}},
	})

	raw, err := json.Marshal(SnapshotOf(st.State()))
	if err != nil {
		t.Fatalf("сериализация: %v", err)
	}
	for _, leak := range []string{"zapreshcheno.invalid", "правило-маячок", "rules", oplog.ActionBlock} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Fatalf("правило просочилось в снапшот через %q: %s", leak, raw)
		}
	}
}

// Выходные узлы клиенту не показываются — ему достаётся только метка о том, что они есть.
//
// Бандл эту границу держит по ТЗ, и снапшот обязан держать ту же: иначе через дверь
// инфраструктуру скрывают, а через окно показывают, и адреса выходных узлов знает каждый, кто
// хоть раз подключился.
func TestSnapshotHidesEgressNodes(t *testing.T) {
	st, owner := openStore(t)
	submit(t, st, owner, 3, oplog.KindNodeAdd, oplog.Node{
		ID:        "qdiver3",
		PublicKey: nodeKey(t),
		Roles:     []string{oplog.RoleEgress},
		Domain:    "qdiver3.example.com",
		Endpoints: []string{"198.51.100.7:443"},
	})

	snap := SnapshotOf(st.State())

	if !snap.HasEgress() {
		t.Fatal("выходной узел есть, а метка о нём не выставлена")
	}
	if len(snap.Nodes) != 1 {
		t.Fatalf("в снапшоте %d узлов, ждали один входной: %+v", len(snap.Nodes), snap.Nodes)
	}
	for _, n := range snap.Nodes {
		if n.ID == "qdiver3" {
			t.Fatalf("выходной узел попал в снапшот: %+v", n)
		}
	}

	// Проверка по сырому виду: узел мог бы уехать не в Nodes, а куда-то ещё. Слово "egress"
	// здесь искать нельзя — так называется сама метка, и она обязана быть.
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("сериализация: %v", err)
	}
	for _, leak := range []string{"qdiver3", "198.51.100.7", "qdiver3.example.com"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Fatalf("в снапшоте нашлось %q: %s", leak, raw)
		}
	}
}

// Правка журнала догоняет клиента сама, без запроса и без опроса по таймеру.
func TestSnapshotFollowsTheLog(t *testing.T) {
	st, owner := openStore(t)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = ServeSnapshots(ctx, server, st, "vasya", nil) }()

	if first := readOne(t, client); first.Settings.BrutalDownMbps != 0 {
		t.Fatalf("потолка быть не должно: %+v", first.Settings)
	}

	submit(t, st, owner, 3, oplog.KindSettingsSet, oplog.Settings{
		BrutalUpMbps:   50,
		BrutalDownMbps: 200,
	})

	second := readOne(t, client)
	if second.Settings.BrutalDownMbps != 200 || second.Settings.BrutalUpMbps != 50 {
		t.Fatalf("новые параметры не доехали: %+v", second.Settings)
	}
}

// Клиенту не место в снапшоте: там не должно быть ничего о других людях сети.
func TestSnapshotCarriesNoClients(t *testing.T) {
	st, owner := openStore(t)
	submit(t, st, owner, 3, oplog.KindClientAdd, oplog.Client{
		ID:        "petya",
		Label:     "Petya",
		PublicKey: nodeKey(t),
		Limits:    oplog.Limits{Devices: 3},
	})

	raw, err := json.Marshal(SnapshotOf(st.State()))
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	for _, secret := range []string{"petya", "Petya"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("снапшот выдаёт другого клиента: %q найдено в %s", secret, raw)
		}
	}
}

func readOne(t *testing.T, r io.Reader) Snapshot {
	t.Helper()
	type result struct {
		snap Snapshot
		err  error
	}
	done := make(chan result, 1)
	go func() {
		frame, err := ReadFrame(r)
		if err != nil {
			done <- result{err: err}
			return
		}
		snap, err := ReadSnapshot(frame.Payload)
		done <- result{snap: snap, err: err}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("чтение снапшота: %v", res.err)
		}
		return res.snap
	case <-time.After(5 * time.Second):
		t.Fatal("снапшот не пришёл")
		return Snapshot{}
	}
}
