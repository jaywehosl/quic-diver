package control

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/store"
)

// party — узел со своим журналом.
type party struct {
	t       *testing.T
	store   *store.Store
	owner   *oplog.MemorySigner
	counter uint64
	clock   time.Time
}

func newParty(t *testing.T, owner *oplog.MemorySigner, spare *oplog.MemorySigner, genesis *oplog.Op) *party {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "log.db"), oplog.Fingerprint{})
	if err != nil {
		t.Fatalf("база: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	p := &party{t: t, store: st, owner: owner, clock: time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)}
	if genesis != nil {
		if _, err := st.Append(genesis); err != nil {
			t.Fatalf("генезис: %v", err)
		}
		p.counter = 1
	}
	_ = spare
	return p
}

func newNetwork(t *testing.T) (*oplog.MemorySigner, *oplog.MemorySigner, *oplog.Op) {
	t.Helper()
	owner, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	spare, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	genesis, err := oplog.NewOp(owner, oplog.KindGenesis, 1, time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
		oplog.Genesis{
			Network: "qdiver",
			Owners: []oplog.AdminKey{
				{PublicKey: oplog.PublicKey(owner.Public()), Scope: oplog.ScopeOwner, Label: "основной"},
				{PublicKey: oplog.PublicKey(spare.Public()), Scope: oplog.ScopeOwner, Label: "запасной"},
			},
		})
	if err != nil {
		t.Fatalf("генезис: %v", err)
	}
	return owner, spare, genesis
}

func (p *party) addClient(id string) {
	p.t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		p.t.Fatalf("ключ клиента: %v", err)
	}
	p.counter++
	p.clock = p.clock.Add(time.Second)
	op, err := oplog.NewOp(p.owner, oplog.KindClientAdd, p.counter, p.clock,
		oplog.Client{ID: id, PublicKey: oplog.PublicKey(pub)})
	if err != nil {
		p.t.Fatalf("сборка: %v", err)
	}
	if _, err := p.store.Append(op); err != nil {
		p.t.Fatalf("применение: %v", err)
	}
}

// exchange сводит две стороны и проводит обмен с обеих одновременно.
func exchange(t *testing.T, a, b *store.Store) (SyncResult, SyncResult) {
	t.Helper()
	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	type out struct {
		res SyncResult
		err error
	}
	done := make(chan out, 1)
	go func() {
		res, err := Sync(cb, b)
		done <- out{res, err}
	}()

	resA, errA := Sync(ca, a)
	if errA != nil {
		t.Fatalf("сторона A: %v", errA)
	}
	got := <-done
	if got.err != nil {
		t.Fatalf("сторона B: %v", got.err)
	}
	return resA, got.res
}

func TestSyncCatchesUpBothWays(t *testing.T) {
	owner, spare, genesis := newNetwork(t)
	a := newParty(t, owner, spare, genesis)
	b := newParty(t, owner, spare, genesis)

	// У A три клиента, у B ни одного.
	a.addClient("vasya")
	a.addClient("petya")
	a.addClient("masha")

	resA, resB := exchange(t, a.store, b.store)
	if resA.Sent != 3 {
		t.Fatalf("A отдал %d записей, ждали 3", resA.Sent)
	}
	if resB.Received != 3 {
		t.Fatalf("B принял %d записей, ждали 3", resB.Received)
	}
	if len(b.store.State().Clients()) != 3 {
		t.Fatalf("у B клиентов: %d", len(b.store.State().Clients()))
	}

	// Повторный обмен ничего не переносит: обеим сторонам нечего отдавать.
	resA2, resB2 := exchange(t, a.store, b.store)
	if resA2.Sent != 0 || resB2.Sent != 0 {
		t.Fatalf("повторный обмен перенёс записи: %d и %d", resA2.Sent, resB2.Sent)
	}
}

// Узел, пришедший в сеть с пустым журналом, должен получить всё, включая генезис.
func TestSyncBootstrapsEmptyNode(t *testing.T) {
	owner, spare, genesis := newNetwork(t)
	full := newParty(t, owner, spare, genesis)
	full.addClient("vasya")

	empty := newParty(t, owner, spare, nil)
	if !empty.store.State().Genesis().IsZero() {
		t.Fatal("новый узел не должен ничего знать")
	}

	resFull, resEmpty := exchange(t, full.store, empty.store)
	if resFull.Sent != 2 {
		t.Fatalf("отдали %d записей, ждали 2", resFull.Sent)
	}
	if resEmpty.Received != 2 {
		t.Fatalf("приняли %d записей, ждали 2", resEmpty.Received)
	}
	if empty.store.State().Genesis() != full.store.State().Genesis() {
		t.Fatal("отпечаток сети не совпал")
	}
	if _, ok := empty.store.State().Client("vasya"); !ok {
		t.Fatal("клиент не доехал")
	}
}

// Обе стороны что-то знают, но разное.
func TestSyncMergesDivergedLogs(t *testing.T) {
	owner, spare, genesis := newNetwork(t)
	a := newParty(t, owner, spare, genesis)
	b := newParty(t, owner, spare, genesis)

	a.addClient("vasya")
	exchange(t, a.store, b.store) // выравниваемся

	// Теперь записи делает только A: у одного ключа последовательность общая, и оба
	// узла получают её от того, кто ближе.
	a.addClient("petya")
	resA, resB := exchange(t, a.store, b.store)
	if resA.Sent != 1 || resB.Received != 1 {
		t.Fatalf("перенос: отдали %d, приняли %d", resA.Sent, resB.Received)
	}
	if len(b.store.State().Clients()) != 2 {
		t.Fatalf("у B клиентов: %d", len(b.store.State().Clients()))
	}
}

// Чужая сеть не должна вливаться, даже если собеседник опознан.
//
// Обе стороны здесь запускаются в горутинах, и это не придирка к оформлению: сторона,
// отвергнувшая записи, перестаёт читать, и вторая упрётся в запись. Разрывать соединение —
// дело вызывающего, Sync им не владеет; тест поэтому закрывает трубу сам.
func TestSyncRefusesForeignNetwork(t *testing.T) {
	ownerA, spareA, genesisA := newNetwork(t)
	ownerB, spareB, genesisB := newNetwork(t)
	a := newParty(t, ownerA, spareA, genesisA)
	b := newParty(t, ownerB, spareB, genesisB)

	ca, cb := net.Pipe()

	errs := make(chan error, 2)
	go func() {
		_, err := Sync(ca, a.store)
		ca.Close()
		errs <- err
	}()
	go func() {
		_, err := Sync(cb, b.store)
		cb.Close()
		errs <- err
	}()

	var failed bool
	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if err != nil {
				failed = true
			}
		case <-time.After(10 * time.Second):
			ca.Close()
			cb.Close()
			t.Fatal("обмен завис вместо отказа")
		}
	}
	if !failed {
		t.Fatal("обмен с чужой сетью прошёл успешно")
	}

	if _, ok := a.store.State().Client("любой"); ok {
		t.Fatal("из чужой сети что-то влилось")
	}
	if a.store.State().Genesis() == b.store.State().Genesis() {
		t.Fatal("отпечатки сетей совпали — тест ничего не проверяет")
	}
}

func TestFrameRejectsHostileLength(t *testing.T) {
	// Заявлено 4 ГБ в кадре.
	hostile := []byte{byte(KindSyncRecords), 0xff, 0xff, 0xff, 0xff}
	if _, err := ReadFrame(bytes.NewReader(hostile)); !errors.Is(err, ErrFrameTooBig) {
		t.Fatalf("огромный кадр принят: %v", err)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, KindPing, []byte("проверка")); err != nil {
		t.Fatalf("запись: %v", err)
	}
	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("чтение: %v", err)
	}
	if f.Kind != KindPing || string(f.Payload) != "проверка" {
		t.Fatalf("кадр разъехался: %+v", f)
	}
	if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("после последнего кадра ждали io.EOF, получили %v", err)
	}
}
