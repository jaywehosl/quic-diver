package store

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// TestEmptyStoreRefusesForeignGenesis — главная проверка первого залива.
//
// Пустой узел принимает журнал от кого угодно: ключей владельцев он ещё не видел, и проверять
// подпись ему не по чему. Вся защита в отпечатке из конфига. Если её нет, посторонний зальёт в
// свежий узел свою сеть — правильно подписанную своим же ключом — и узел станет чужим.
func TestEmptyStoreRefusesForeignGenesis(t *testing.T) {
	ours, theirs := newHarness(t), newHarness(t)

	fp, err := oplog.FingerprintOf(ours.genesis)
	if err != nil {
		t.Fatalf("отпечаток: %v", err)
	}

	// Свежий узел с нашим отпечатком в конфиге и пустым журналом — ровно то состояние, в
	// котором он встречает первый залив.
	fresh, err := Open(filepath.Join(t.TempDir(), "fresh.db"), fp)
	if err != nil {
		t.Fatalf("открытие: %v", err)
	}
	defer fresh.Close()
	if !fresh.State().Genesis().IsZero() {
		t.Fatal("новая база не пуста")
	}

	var foreign bytes.Buffer
	if err := theirs.store.Export(&foreign); err != nil {
		t.Fatalf("выгрузка чужого журнала: %v", err)
	}
	if _, err := fresh.Import(&foreign); !errors.Is(err, ErrWrongNetwork) {
		t.Fatalf("чужой журнал принят в пустой узел: %v", err)
	}
	if !fresh.State().Genesis().IsZero() {
		t.Fatal("чужой генезис осел в базе")
	}

	var mine bytes.Buffer
	if err := ours.store.Export(&mine); err != nil {
		t.Fatalf("выгрузка своего журнала: %v", err)
	}
	if _, err := fresh.Import(&mine); err != nil {
		t.Fatalf("свой журнал не принят: %v", err)
	}
	if fresh.State().Genesis() != fp {
		t.Fatalf("отпечаток после залива %s, ожидался %s", fresh.State().Genesis(), fp)
	}
}

// TestAdminStoreTakesAnyGenesis — обратная сторона: у администратора отпечатка нет и быть не
// может, сеть в этот момент только рождается.
func TestAdminStoreTakesAnyGenesis(t *testing.T) {
	h := newHarness(t)

	blank, err := Open(filepath.Join(t.TempDir(), "admin.db"), oplog.Fingerprint{})
	if err != nil {
		t.Fatalf("открытие: %v", err)
	}
	defer blank.Close()

	if _, err := blank.Append(h.genesis); err != nil {
		t.Fatalf("генезис не принят базой без отпечатка: %v", err)
	}
}
