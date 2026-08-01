package ownerlog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jaywehosl/quic-diver/internal/bundle"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}

func created(t *testing.T, password string) Result {
	t.Helper()
	res, err := Create(Params{
		Network:  "qdiver",
		Password: password,
		Settings: oplog.Settings{BrutalUpMbps: 100, BrutalDownMbps: 300, BrutalMeshMbps: 500},
		Now:      fixedClock(),
	})
	if err != nil {
		t.Fatalf("создание сети: %v", err)
	}
	return res
}

// withNode добавляет в журнал узел — так, как это делает включение узла в сеть.
func withNode(t *testing.T, res Result, id, domain string) {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ключ узла: %v", err)
	}
	signer, err := oplog.NewMemorySigner(res.WorkingKey)
	if err != nil {
		t.Fatalf("ключ владельца: %v", err)
	}
	op, err := oplog.NewOp(signer, oplog.KindNodeAdd, res.Journal.Next(signer.KeyID()),
		time.Date(2026, 8, 1, 13, 0, 0, 0, time.UTC), oplog.Node{
			ID:        id,
			PublicKey: oplog.PublicKey(pub),
			Roles:     []string{"ingress"},
			Domain:    domain,
			Endpoints: []string{"203.0.113.1:443", "[2001:db8::1]:443"},
		})
	if err != nil {
		t.Fatalf("запись об узле: %v", err)
	}
	if _, err := res.Journal.Append(op); err != nil {
		t.Fatalf("узел не применился: %v", err)
	}
}

// Сеть создаётся на устройстве целиком: два ключа владельца и генезис.
func TestCreateMakesTwoOwnerKeys(t *testing.T) {
	res := created(t, "пароль")

	if res.Genesis.IsZero() {
		t.Fatal("отпечаток не посчитан")
	}
	if bytes.Equal(res.WorkingKey, res.SpareKey) {
		t.Fatal("рабочий и запасной ключи совпали — восстанавливаться будет нечем")
	}

	owners := res.Journal.State().Admins()
	if len(owners) != 2 {
		t.Fatalf("владельцев %d, ожидалось 2", len(owners))
	}
	for _, o := range owners {
		if o.Scope != oplog.ScopeOwner {
			t.Fatalf("ключ %s с областью %s", o.ID(), o.Scope)
		}
	}

	// Параметры сети — вторая запись: генезис говорит, чья сеть, а не какие в ней потолки.
	if res.Journal.Len() != 2 {
		t.Fatalf("записей в журнале %d, ожидалось 2", res.Journal.Len())
	}
	if got := res.Journal.State().Settings().BrutalMeshMbps; got != 500 {
		t.Fatalf("потолок между узлами %d, задавали 500", got)
	}
}

// Ссылка выдаётся только после того, как в сети появился узел.
//
// Иначе получается ключ без адреса: владелец не может подключиться к собственной сети, а
// потеряв журнал — теряет её совсем. Ровно это и вышло при первой обкатке.
func TestBundlesRefusedWhileNetworkHasNoNodes(t *testing.T) {
	res := created(t, "пароль")

	_, _, err := IssueBundles(res.Journal, res.WorkingKey, res.SpareKey, "пароль")
	if err == nil {
		t.Fatal("ссылка выдана для сети без единого узла")
	}
	if !strings.Contains(err.Error(), "входного узла") {
		t.Fatalf("причина отказа невнятная: %v", err)
	}
}

// Обе ссылки открываются одним паролем, ведут в ту же сеть и несут узлы с потолками.
func TestOwnerBundlesCarryNodesAndSettings(t *testing.T) {
	res := created(t, "пароль")
	withNode(t, res, "node1", "one.example")

	working, spare, err := IssueBundles(res.Journal, res.WorkingKey, res.SpareKey, "пароль")
	if err != nil {
		t.Fatalf("выдача ссылок: %v", err)
	}
	if working == spare {
		t.Fatal("рабочая и запасная ссылки совпали")
	}

	for name, uri := range map[string]string{"рабочая": working, "запасная": spare} {
		if _, err := bundle.Decode(uri, ""); !errors.Is(err, bundle.ErrNeedPassword) {
			t.Fatalf("%s ссылка открылась без пароля: %v", name, err)
		}
		b, err := bundle.Decode(uri, "пароль")
		if err != nil {
			t.Fatalf("%s ссылка не открылась: %v", name, err)
		}
		if !b.Owner {
			t.Fatalf("%s ссылка не помечена владельческой", name)
		}
		if b.Genesis != res.Genesis {
			t.Fatalf("%s ссылка ведёт в другую сеть", name)
		}
		// Ради этого выдача и перенесена в конец: ключ без адреса никуда не ведёт.
		if len(b.Ingress) != 1 || b.Ingress[0].ID != "node1" {
			t.Fatalf("%s ссылка без узлов: %+v", name, b.Ingress)
		}
		if len(b.Ingress[0].Endpoints) != 2 {
			t.Fatalf("%s ссылка потеряла адреса узла: %v", name, b.Ingress[0].Endpoints)
		}
		// Потолки: без них клиент поднимется на обычном Cubic, а человек будет уверен, что
		// работает BRUTAL, который он задавал.
		if b.Settings.BrutalUpMbps != 100 || b.Settings.BrutalDownMbps != 300 {
			t.Fatalf("%s ссылка без потолков: %+v", name, b.Settings)
		}
	}
}

// Ключ в ссылке владельца — это ключ из генезиса, а не посторонний.
func TestOwnerBundleCarriesGenesisKey(t *testing.T) {
	res := created(t, "")
	withNode(t, res, "node1", "one.example")

	working, _, err := IssueBundles(res.Journal, res.WorkingKey, res.SpareKey, "")
	if err != nil {
		t.Fatalf("выдача ссылок: %v", err)
	}

	b, err := bundle.Decode(working, "")
	if err != nil {
		t.Fatalf("ссылка не открылась: %v", err)
	}
	if !bytes.Equal(b.ClientKey, res.WorkingKey) {
		t.Fatal("в рабочей ссылке не тот ключ, что отдан приложению")
	}

	signer, err := oplog.NewMemorySigner(res.WorkingKey)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	var found bool
	for _, o := range res.Journal.State().Admins() {
		if o.ID() == signer.KeyID() {
			found = true
		}
	}
	if !found {
		t.Fatal("ключ рабочей ссылки не объявлен владельцем в генезисе")
	}
}

// Журнал переживает запись и чтение байт в байт: подпись покрывает конкретные байты.
func TestJournalRoundTrip(t *testing.T) {
	res := created(t, "")

	raw, err := res.Journal.Bytes()
	if err != nil {
		t.Fatalf("выгрузка: %v", err)
	}
	back, err := Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if back.Genesis() != res.Genesis {
		t.Fatal("после круга другой отпечаток")
	}
	if back.Len() != res.Journal.Len() {
		t.Fatalf("записей после круга %d, было %d", back.Len(), res.Journal.Len())
	}

	again, err := back.Bytes()
	if err != nil {
		t.Fatalf("повторная выгрузка: %v", err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("байты изменились при пересборке — подпись стала непроверяемой")
	}
}

// Счётчик ключа берётся из журнала, а не с нуля: узел, увидевший повтор, запись отвергнет.
func TestNextCounterFollowsJournal(t *testing.T) {
	res := created(t, "")

	signer, err := oplog.NewMemorySigner(res.WorkingKey)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	// Генезис и параметры сети — две записи одного ключа, значит следующая третья.
	if got := res.Journal.Next(signer.KeyID()); got != 3 {
		t.Fatalf("следующий счётчик %d, ожидался 3", got)
	}
}

// Ключ развёртывания переживает круг и ловит опечатку контрольной суммой.
func TestDeployKeyRoundTripAndChecksum(t *testing.T) {
	res := created(t, "")

	key, err := EncodeDeploy(res.Journal.DeployFor("qdiver1", "one.example", []string{"ingress"}))
	if err != nil {
		t.Fatalf("сборка ключа: %v", err)
	}
	if !strings.HasPrefix(key, DeployScheme) {
		t.Fatalf("ключ без приставки: %s", key)
	}

	d, err := DecodeDeploy(key)
	if err != nil {
		t.Fatalf("разбор ключа: %v", err)
	}
	if d.Genesis != res.Genesis || d.ID != "qdiver1" || d.Domain != "one.example" {
		t.Fatalf("разобралось не то: %+v", d)
	}
	if d.Settings.BrutalMeshMbps != 500 {
		t.Fatalf("потолки не доехали: %+v", d.Settings)
	}
	// Узлов в сети ещё нет — списку соседей неоткуда взяться, и первый узел получит журнал
	// от клиента.
	if len(d.Peers) != 0 {
		t.Fatalf("в ключе первого узла есть соседи: %v", d.Peers)
	}

	// Опечатка в одном знаке: без суммы узел поднялся бы с испорченным отпечатком и молча
	// не принял бы журнал.
	broken := []byte(key)
	i := len(DeployScheme) + 3
	if broken[i] == 'A' {
		broken[i] = 'B'
	} else {
		broken[i] = 'A'
	}
	if _, err := DecodeDeploy(string(broken)); !errors.Is(err, ErrDeployBroken) {
		t.Fatalf("испорченный ключ принят: %v", err)
	}

	if _, err := DecodeDeploy("qdiver://что-то"); !errors.Is(err, ErrNotDeployKey) {
		t.Fatalf("ссылка бандла принята за ключ развёртывания: %v", err)
	}
}

// Пустой журнал ничего не включает: сети ещё нет.
func TestAdoptNeedsNetwork(t *testing.T) {
	j := New()
	_, err := j.Adopt(t.Context(), AdoptParams{Addr: "one.example", Roles: []string{"ingress"}})
	if !errors.Is(err, ErrNoGenesis) {
		t.Fatalf("включение узла в несуществующую сеть: %v", err)
	}
}
