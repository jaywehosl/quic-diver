package control

import (
	"crypto/ed25519"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/store"
)

// TestSyncNamesScopeViolation — отказ по правам обязан назвать причину.
//
// Оператор, полезший в записи владельца, иначе увидел бы обрыв связи и пошёл искать сеть.
// Причина отказа лежит в журнале узла, куда человек с телефона не заглянет никогда.
func TestSyncNamesScopeViolation(t *testing.T) {
	owner, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("ключ владельца: %v", err)
	}
	spare, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("запасной ключ: %v", err)
	}
	operator, err := oplog.GenerateSigner()
	if err != nil {
		t.Fatalf("ключ оператора: %v", err)
	}
	clock := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	genesis, err := oplog.NewOp(owner, oplog.KindGenesis, 1, clock, oplog.Genesis{
		Network: "qdiver",
		Owners: []oplog.AdminKey{
			{PublicKey: oplog.PublicKey(owner.Public()), Scope: oplog.ScopeOwner, Label: "рабочий"},
			{PublicKey: oplog.PublicKey(spare.Public()), Scope: oplog.ScopeOwner, Label: "запасной"},
		},
	})
	if err != nil {
		t.Fatalf("генезис: %v", err)
	}
	// Оператор появляется отдельной записью: в генезисе бывают только владельцы.
	grant, err := oplog.NewOp(owner, oplog.KindAdminAdd, 2, clock.Add(time.Second), oplog.AdminAdd{
		Key: oplog.AdminKey{PublicKey: oplog.PublicKey(operator.Public()), Scope: oplog.ScopeOperator, Label: "оператор"},
	})
	if err != nil {
		t.Fatalf("выдача прав оператору: %v", err)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "log.db"), oplog.Fingerprint{})
	if err != nil {
		t.Fatalf("база: %v", err)
	}
	defer st.Close()
	for _, op := range []*oplog.Op{genesis, grant} {
		if _, err := st.Append(op); err != nil {
			t.Fatalf("применение %s: %v", op.Kind, err)
		}
	}

	// Узел — операция владельца, подписанная оператором. Ключ узлу известен, подпись сходится,
	// не хватает ровно прав: иначе отказ пришёл бы по другой причине и тест ничего не доказал.
	nodeKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ключ узла: %v", err)
	}
	bad, err := oplog.NewOp(operator, oplog.KindNodeAdd, 1, clock.Add(2*time.Second), oplog.Node{
		ID:        "qdiver9",
		PublicKey: oplog.PublicKey(nodeKey),
		Roles:     []string{"ingress"},
		Domain:    "qdiver9.example",
		Endpoints: []string{"203.0.113.9:443"},
	})
	if err != nil {
		t.Fatalf("сборка записи: %v", err)
	}
	raw, err := bad.Bytes()
	if err != nil {
		t.Fatalf("байты записи: %v", err)
	}

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	done := make(chan error, 1)
	go func() {
		_, err := Sync(cb, st)
		done <- err
	}()

	// Играем оператора вручную: класть такую запись в собственный журнал нельзя, его же
	// проверка её и отвергнет.
	//
	// Пишем из отдельной горутины и читаем одновременно — по той же причине, по какой это
	// делает сам Sync: труба синхронная, и сторона, пишущая не читая, встанет, как только
	// собеседник начнёт писать в ответ.
	go func() {
		_ = WriteFrame(ca, KindSyncOffer, []byte(`{"counters":{}}`))
		_ = WriteFrame(ca, KindSyncRecords, raw)
		_ = WriteFrame(ca, KindSyncDone, nil)
	}()

	// Узел присылает предложение, свои записи — и следом отказ на наши.
	var reject *Frame
	for i := 0; i < 8 && reject == nil; i++ {
		f, err := ReadFrame(ca)
		if err != nil {
			t.Fatalf("чтение ответа: %v", err)
		}
		if f.Kind == KindReject {
			reject = f
		}
	}
	if reject == nil {
		t.Fatal("отказ не пришёл")
	}

	reason := string(reject.Payload)
	if !strings.Contains(reason, "прав") {
		t.Fatalf("причина не про права: %q", reason)
	}
	if !strings.Contains(reason, oplog.KindNodeAdd.String()) {
		t.Fatalf("в причине нет вида операции: %q", reason)
	}

	// Та же причина обязана дойти до вызывающего, а не осесть в журнале узла.
	if err := rejected(reject); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "прав") {
		t.Fatalf("разбор отказа: %v", err)
	}

	if err := <-done; !errors.Is(err, oplog.ErrForbidden) {
		t.Fatalf("узел вернул не отказ по правам: %v", err)
	}
	if _, ok := st.State().Node("qdiver9"); ok {
		t.Fatal("запись без прав всё-таки применилась")
	}
}
