package ownerlog

import (
	"bytes"
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

// Сеть создаётся на устройстве целиком: два ключа владельца, генезис, обе ссылки.
func TestCreateMakesTwoOwnerKeys(t *testing.T) {
	res := created(t, "пароль")

	if res.Genesis.IsZero() {
		t.Fatal("отпечаток не посчитан")
	}
	if res.Working == res.Spare {
		t.Fatal("рабочая и запасная ссылки совпали — восстанавливаться будет нечем")
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

// Обе ссылки открываются одним паролем и ведут в ту же сеть.
func TestOwnerBundlesOpenWithPassword(t *testing.T) {
	res := created(t, "пароль")

	for name, uri := range map[string]string{"рабочая": res.Working, "запасная": res.Spare} {
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
		// Узлов в ней нет и быть не может: сеть только что родилась, серверов не существует.
		if len(b.Ingress) != 0 {
			t.Fatalf("%s ссылка несёт узлы, которых ещё нет", name)
		}
	}
}

// Ключ клиента в ссылке владельца — это ключ из генезиса, а не посторонний.
func TestOwnerBundleCarriesGenesisKey(t *testing.T) {
	res := created(t, "")

	b, err := bundle.Decode(res.Working, "")
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
