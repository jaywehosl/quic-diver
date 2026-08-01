package store

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// harness — сеть из двух владельцев поверх временной базы.
type harness struct {
	t       *testing.T
	store   *Store
	path    string
	owners  [2]*oplog.MemorySigner
	counter map[oplog.KeyID]uint64
	clock   time.Time
	genesis *oplog.Op
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	path := filepath.Join(t.TempDir(), "qdiver.db")
	st, err := Open(path, oplog.Fingerprint{})
	if err != nil {
		t.Fatalf("открытие базы: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	h := &harness{
		t:       t,
		store:   st,
		path:    path,
		counter: make(map[oplog.KeyID]uint64),
		clock:   time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
	}
	for i := range h.owners {
		s, err := oplog.GenerateSigner()
		if err != nil {
			t.Fatalf("генерация ключа: %v", err)
		}
		h.owners[i] = s
	}

	h.genesis = h.sign(h.owners[0], oplog.KindGenesis, oplog.Genesis{
		Network: "qdiver",
		Owners: []oplog.AdminKey{
			{PublicKey: oplog.PublicKey(h.owners[0].Public()), Scope: oplog.ScopeOwner, Label: "основной"},
			{PublicKey: oplog.PublicKey(h.owners[1].Public()), Scope: oplog.ScopeOwner, Label: "запасной"},
		},
	})
	if _, err := st.Append(h.genesis); err != nil {
		t.Fatalf("генезис: %v", err)
	}
	return h
}

func (h *harness) sign(s *oplog.MemorySigner, kind oplog.Kind, payload any) *oplog.Op {
	h.t.Helper()
	id := s.KeyID()
	h.counter[id]++
	h.clock = h.clock.Add(time.Second)
	op, err := oplog.NewOp(s, kind, h.counter[id], h.clock, payload)
	if err != nil {
		h.t.Fatalf("сборка %s: %v", kind, err)
	}
	return op
}

func (h *harness) addClient(id string) *oplog.Op {
	h.t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		h.t.Fatalf("генерация ключа клиента: %v", err)
	}
	op := h.sign(h.owners[0], oplog.KindClientAdd, oplog.Client{
		ID:        id,
		PublicKey: oplog.PublicKey(pub),
		Limits:    oplog.Limits{Devices: 3},
	})
	if _, err := h.store.Append(op); err != nil {
		h.t.Fatalf("добавление клиента %s: %v", id, err)
	}
	return op
}

func TestStateSurvivesRestart(t *testing.T) {
	h := newHarness(t)
	h.addClient("vasya")
	h.addClient("petya")

	want := h.store.State().Genesis()
	if err := h.store.Close(); err != nil {
		t.Fatalf("закрытие: %v", err)
	}

	reopened, err := Open(h.path, want)
	if err != nil {
		t.Fatalf("повторное открытие: %v", err)
	}
	defer reopened.Close()

	if got := reopened.State().Genesis(); got != want {
		t.Fatalf("отпечаток сети не пережил перезапуск: %s против %s", got, want)
	}
	if len(reopened.State().Clients()) != 2 {
		t.Fatalf("клиенты не восстановились: %d", len(reopened.State().Clients()))
	}
	if _, ok := reopened.State().Client("vasya"); !ok {
		t.Fatal("клиент vasya пропал")
	}
}

// Восстановление обязано уважать причинность: операция оператора законна только после
// записи, выдавшей ему права. Порядок (ключ, счётчик) сломал бы это при неудачном
// соседстве идентификаторов, поэтому применяем в порядке приёма.
func TestReplayRespectsCausality(t *testing.T) {
	h := newHarness(t)

	bot, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}
	grant := h.sign(h.owners[0], oplog.KindAdminAdd, oplog.AdminAdd{Key: oplog.AdminKey{
		PublicKey: oplog.PublicKey(bot.Public()), Scope: oplog.ScopeOperator, Label: "бот",
	}})
	if _, err := h.store.Append(grant); err != nil {
		t.Fatalf("выдача прав: %v", err)
	}

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("генерация ключа клиента: %v", err)
	}
	byBot := h.sign(bot, oplog.KindClientAdd, oplog.Client{
		ID: "fromBot", PublicKey: oplog.PublicKey(pub),
	})
	if _, err := h.store.Append(byBot); err != nil {
		t.Fatalf("операция бота: %v", err)
	}

	h.store.Close()
	reopened, err := Open(h.path, oplog.Fingerprint{})
	if err != nil {
		t.Fatalf("повторное открытие: %v", err)
	}
	defer reopened.Close()

	if _, ok := reopened.State().Client("fromBot"); !ok {
		t.Fatal("клиент, заведённый оператором, не пережил перезапуск")
	}
}

func TestAppendRejectsUnverifiableRecord(t *testing.T) {
	h := newHarness(t)

	outsider, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	op, err := oplog.NewOp(outsider, oplog.KindClientAdd, 1, h.clock, oplog.Client{
		ID: "chuzhoy", PublicKey: oplog.PublicKey(pub),
	})
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}

	if _, err := h.store.Append(op); !errors.Is(err, oplog.ErrUnknownKey) {
		t.Fatalf("запись от постороннего принята: %v", err)
	}
	n, err := h.store.Len()
	if err != nil {
		t.Fatalf("подсчёт: %v", err)
	}
	if n != 1 {
		t.Fatalf("отвергнутая запись всё-таки попала в базу: записей %d", n)
	}
}

func TestDuplicateAppendRejected(t *testing.T) {
	h := newHarness(t)
	op := h.addClient("vasya")

	if _, err := h.store.Append(op); !errors.Is(err, oplog.ErrReplay) {
		t.Fatalf("повторная запись принята: %v", err)
	}
	n, _ := h.store.Len()
	if n != 2 {
		t.Fatalf("повтор попал в базу: записей %d", n)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	h := newHarness(t)
	h.addClient("vasya")
	h.addClient("petya")

	var dump bytes.Buffer
	if err := h.store.Export(&dump); err != nil {
		t.Fatalf("выгрузка: %v", err)
	}

	fresh := filepath.Join(t.TempDir(), "restored.db")
	restored, err := Open(fresh, oplog.Fingerprint{})
	if err != nil {
		t.Fatalf("открытие чистой базы: %v", err)
	}
	defer restored.Close()

	n, err := restored.Import(&dump)
	if err != nil {
		t.Fatalf("вливание: %v", err)
	}
	if n != 3 {
		t.Fatalf("влилось записей: %d, ждали 3", n)
	}
	if restored.State().Genesis() != h.store.State().Genesis() {
		t.Fatal("отпечаток сети после раскатки другой")
	}
	if len(restored.State().Clients()) != 2 {
		t.Fatalf("клиенты после раскатки: %d", len(restored.State().Clients()))
	}
}

// Журнал разносится между узлами, и сосед всегда присылает в том числе то, что у нас уже
// есть. Повторное вливание обязано быть тихим, иначе обмен падал бы на каждом круге.
func TestImportIsIdempotent(t *testing.T) {
	h := newHarness(t)
	h.addClient("vasya")

	var dump bytes.Buffer
	if err := h.store.Export(&dump); err != nil {
		t.Fatalf("выгрузка: %v", err)
	}
	raw := dump.Bytes()

	fresh := filepath.Join(t.TempDir(), "restored.db")
	restored, err := Open(fresh, oplog.Fingerprint{})
	if err != nil {
		t.Fatalf("открытие: %v", err)
	}
	defer restored.Close()

	first, err := restored.Import(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("первое вливание: %v", err)
	}
	if first != 2 {
		t.Fatalf("влилось %d записей, ждали 2", first)
	}

	second, err := restored.Import(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("повторное вливание: %v", err)
	}
	if second != 0 {
		t.Fatalf("повторное вливание добавило %d записей", second)
	}

	// Дозалив: добавляем клиента у первого и вливаем весь файл заново.
	h.addClient("petya")
	dump.Reset()
	if err := h.store.Export(&dump); err != nil {
		t.Fatalf("выгрузка: %v", err)
	}
	third, err := restored.Import(&dump)
	if err != nil {
		t.Fatalf("дозалив: %v", err)
	}
	if third != 1 {
		t.Fatalf("дозалив добавил %d записей, ждали 1", third)
	}
	if _, ok := restored.State().Client("petya"); !ok {
		t.Fatal("дозалитый клиент не появился")
	}
}

// Чужой журнал не должен приниматься за свой даже при совпадении всего остального.
func TestImportRejectsForeignGenesis(t *testing.T) {
	ours := newHarness(t)
	theirs := newHarness(t)

	var dump bytes.Buffer
	if err := theirs.store.Export(&dump); err != nil {
		t.Fatalf("выгрузка: %v", err)
	}
	if _, err := ours.store.Import(&dump); !errors.Is(err, ErrWrongNetwork) {
		t.Fatalf("чужой генезис принят: %v", err)
	}
}

// Бэкап подписан целиком, поэтому подделанный файл не должен вливаться.
func TestImportRejectsTamperedDump(t *testing.T) {
	h := newHarness(t)
	h.addClient("vasya")

	var dump bytes.Buffer
	if err := h.store.Export(&dump); err != nil {
		t.Fatalf("выгрузка: %v", err)
	}
	raw := dump.Bytes()
	// Портим последний байт подписи последней записи.
	raw[len(raw)-1] ^= 0xff

	fresh := filepath.Join(t.TempDir(), "tampered.db")
	restored, err := Open(fresh, oplog.Fingerprint{})
	if err != nil {
		t.Fatalf("открытие: %v", err)
	}
	defer restored.Close()

	if _, err := restored.Import(bytes.NewReader(raw)); err == nil {
		t.Fatal("подделанный бэкап влился")
	}
}

func TestOpenRejectsForeignNetwork(t *testing.T) {
	h := newHarness(t)
	h.store.Close()

	var alien oplog.Fingerprint
	alien[0] = 0xaa
	if _, err := Open(h.path, alien); !errors.Is(err, ErrWrongNetwork) {
		t.Fatalf("чужая сеть принята: %v", err)
	}
}

// Обмен с соседом: отдаём ровно то, чего у него нет.
func TestSinceGivesOnlyMissing(t *testing.T) {
	h := newHarness(t)
	h.addClient("vasya")
	h.addClient("petya")

	all, err := h.store.Since(nil)
	if err != nil {
		t.Fatalf("выборка: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("сосед без ничего должен получить всё: %d", len(all))
	}

	upToDate := h.store.Counters()
	none, err := h.store.Since(upToDate)
	if err != nil {
		t.Fatalf("выборка: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("соседу, у которого всё есть, отдали %d записей", len(none))
	}

	behind := map[oplog.KeyID]uint64{h.owners[0].KeyID(): 2}
	tail, err := h.store.Since(behind)
	if err != nil {
		t.Fatalf("выборка: %v", err)
	}
	if len(tail) != 1 {
		t.Fatalf("отставшему на одну отдали %d записей", len(tail))
	}
	if tail[0].Counter != 3 {
		t.Fatalf("отдали не ту запись: счётчик %d", tail[0].Counter)
	}
}

func TestEmptyStoreHasNoGenesis(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	st, err := Open(path, oplog.Fingerprint{})
	if err != nil {
		t.Fatalf("открытие: %v", err)
	}
	defer st.Close()

	if !st.State().Genesis().IsZero() {
		t.Fatal("у пустой базы взялся отпечаток сети")
	}
	n, err := st.Len()
	if err != nil {
		t.Fatalf("подсчёт: %v", err)
	}
	if n != 0 {
		t.Fatalf("пустая база содержит %d записей", n)
	}
}
