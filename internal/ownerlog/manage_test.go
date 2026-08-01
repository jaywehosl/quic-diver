package ownerlog

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/jaywehosl/quic-diver/internal/bundle"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// network заводит сеть с одним входным узлом — состояние, в котором можно управлять.
func network(t *testing.T) Result {
	t.Helper()
	res := created(t, "")
	withNode(t, res, "node1", "one.example")
	return res
}

// Клиент заводится, получает ссылку с узлами и попадает в журнал.
func TestAddClientIssuesUsableBundle(t *testing.T) {
	res := network(t)

	uri, err := res.Journal.AddClient(res.WorkingKey, ClientParams{
		ID:            "vasya",
		Label:         "телефон",
		TrafficBytes:  100 << 30,
		TrafficPeriod: "monthly",
		Devices:       2,
	}, "пароль")
	if err != nil {
		t.Fatalf("заведение клиента: %v", err)
	}

	c, ok := res.Journal.State().Client("vasya")
	if !ok {
		t.Fatal("клиента нет в журнале")
	}
	if c.Limits.Devices != 2 || c.Limits.TrafficBytes != 100<<30 || c.Limits.TrafficPeriod != "monthly" {
		t.Fatalf("лимиты записаны неверно: %+v", c.Limits)
	}

	b, err := bundle.Decode(uri, "пароль")
	if err != nil {
		t.Fatalf("ссылка не открылась: %v", err)
	}
	if b.Owner {
		t.Fatal("обычному клиенту досталась ссылка владельца")
	}
	if len(b.Ingress) != 1 || b.Ingress[0].ID != "node1" {
		t.Fatalf("в ссылке нет узлов: %+v", b.Ingress)
	}
	// Приватная часть уезжает в ссылку, публичная — в журнал. Проверяем, что это одна пара.
	signer, err := oplog.NewMemorySigner(b.ClientKey)
	if err != nil {
		t.Fatalf("ключ из ссылки: %v", err)
	}
	if oplog.KeyIDOf(signer.Public()) != oplog.KeyIDOf(ed25519.PublicKey(c.PublicKey)) {
		t.Fatal("ключ в ссылке не тот, что записан в журнале")
	}
}

// Ссылка без узлов бесполезна — тот же урок, что и со ссылкой владельца.
func TestAddClientRefusedWithoutNodes(t *testing.T) {
	res := created(t, "")

	_, err := res.Journal.AddClient(res.WorkingKey, ClientParams{ID: "vasya"}, "")
	if err == nil {
		t.Fatal("клиент заведён в сети без узлов")
	}
	if !strings.Contains(err.Error(), "входных узлов") {
		t.Fatalf("причина отказа невнятная: %v", err)
	}
}

// Имя занято — второй раз не заводится: иначе первая ссылка молча перестала бы работать.
func TestAddClientRefusesDuplicate(t *testing.T) {
	res := network(t)

	if _, err := res.Journal.AddClient(res.WorkingKey, ClientParams{ID: "vasya"}, ""); err != nil {
		t.Fatalf("первый: %v", err)
	}
	if _, err := res.Journal.AddClient(res.WorkingKey, ClientParams{ID: "vasya"}, ""); err == nil {
		t.Fatal("клиент с занятым именем заведён")
	}
}

// Приостановка обратима, отзыв — нет.
func TestSuspendAndRevoke(t *testing.T) {
	res := network(t)
	if _, err := res.Journal.AddClient(res.WorkingKey, ClientParams{ID: "vasya"}, ""); err != nil {
		t.Fatalf("клиент: %v", err)
	}

	if err := res.Journal.SuspendClient(res.WorkingKey, "vasya", true); err != nil {
		t.Fatalf("приостановка: %v", err)
	}
	c, _ := res.Journal.State().Client("vasya")
	if !c.Suspended {
		t.Fatal("клиент не приостановлен")
	}

	if err := res.Journal.SuspendClient(res.WorkingKey, "vasya", false); err != nil {
		t.Fatalf("возврат: %v", err)
	}
	c, _ = res.Journal.State().Client("vasya")
	if c.Suspended {
		t.Fatal("клиент не вернулся в строй")
	}

	if err := res.Journal.RevokeClient(res.WorkingKey, "vasya"); err != nil {
		t.Fatalf("отзыв: %v", err)
	}
	if _, ok := res.Journal.State().Client("vasya"); ok {
		t.Fatal("отозванный клиент остался в сети")
	}
}

// Перевыпуск меняет ключ, сохраняя лимиты: ссылка утекла, а человек тот же.
func TestReissueKeepsLimitsChangesKey(t *testing.T) {
	res := network(t)
	first, err := res.Journal.AddClient(res.WorkingKey, ClientParams{
		ID: "vasya", TrafficBytes: 50 << 30, TrafficPeriod: "monthly", Devices: 3,
	}, "")
	if err != nil {
		t.Fatalf("клиент: %v", err)
	}

	second, err := res.Journal.ReissueClient(res.WorkingKey, "vasya", "")
	if err != nil {
		t.Fatalf("перевыпуск: %v", err)
	}
	if first == second {
		t.Fatal("ссылка не изменилась — старая осталась бы рабочей")
	}

	before, _ := bundle.Decode(first, "")
	after, _ := bundle.Decode(second, "")
	if string(before.ClientKey) == string(after.ClientKey) {
		t.Fatal("ключ не сменился")
	}

	c, _ := res.Journal.State().Client("vasya")
	if c.Limits.TrafficBytes != 50<<30 || c.Limits.Devices != 3 {
		t.Fatalf("лимиты потерялись при перевыпуске: %+v", c.Limits)
	}
	// В журнале должен лежать новый ключ, иначе узел пустит по старому.
	signer, _ := oplog.NewMemorySigner(after.ClientKey)
	if oplog.KeyIDOf(signer.Public()) != oplog.KeyIDOf(ed25519.PublicKey(c.PublicKey)) {
		t.Fatal("в журнале остался прежний ключ")
	}
}

// Последний входной узел не отзывается: это отрезало бы всех, включая самого владельца.
func TestRevokeLastIngressRefused(t *testing.T) {
	res := network(t)

	err := res.Journal.RevokeNode(res.WorkingKey, "node1")
	if err == nil {
		t.Fatal("последний входной узел отозван")
	}
	if !strings.Contains(err.Error(), "последний входной") {
		t.Fatalf("причина отказа невнятная: %v", err)
	}

	withNode(t, res, "node2", "two.example")
	if err := res.Journal.RevokeNode(res.WorkingKey, "node1"); err != nil {
		t.Fatalf("отзыв при двух узлах: %v", err)
	}
	if _, ok := res.Journal.State().Node("node1"); ok {
		t.Fatal("узел остался в сети")
	}
}

// Параметры меняются записью, и сброс кеша имён — тоже состояние, а не команда.
func TestSettingsAndFlush(t *testing.T) {
	res := network(t)

	if err := res.Journal.SetSettings(res.WorkingKey, oplog.Settings{
		BrutalUpMbps: 700, BrutalDownMbps: 700, BrutalMeshMbps: 900,
	}); err != nil {
		t.Fatalf("параметры: %v", err)
	}
	if got := res.Journal.State().Settings().BrutalMeshMbps; got != 900 {
		t.Fatalf("потолок между узлами %d, задавали 900", got)
	}

	before := res.Journal.State().Settings().DNSFlushAt
	if err := res.Journal.FlushDNS(res.WorkingKey); err != nil {
		t.Fatalf("сброс кеша: %v", err)
	}
	after := res.Journal.State().Settings()
	if after.DNSFlushAt <= before {
		t.Fatalf("метка сброса не сдвинулась: было %d, стало %d", before, after.DNSFlushAt)
	}
	// Остальные параметры при сбросе не должны потеряться: это одна запись на всё.
	if after.BrutalMeshMbps != 900 {
		t.Fatalf("сброс кеша затёр потолки: %+v", after)
	}
}

// Счётчик ключа растёт с каждой записью: узел, увидевший повтор, отвергнет её.
func TestOperationsAdvanceCounter(t *testing.T) {
	res := network(t)
	signer, err := oplog.NewMemorySigner(res.WorkingKey)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	start := res.Journal.Next(signer.KeyID())

	if _, err := res.Journal.AddClient(res.WorkingKey, ClientParams{ID: "vasya"}, ""); err != nil {
		t.Fatalf("клиент: %v", err)
	}
	if err := res.Journal.SetSettings(res.WorkingKey, oplog.Settings{BrutalUpMbps: 100}); err != nil {
		t.Fatalf("параметры: %v", err)
	}

	if got := res.Journal.Next(signer.KeyID()); got != start+2 {
		t.Fatalf("счётчик %d, ожидался %d", got, start+2)
	}
}

// Журнал владельца участвует в обмене наравне с узловым: отдаёт недостающее и принимает чужое.
func TestJournalActsAsSyncLog(t *testing.T) {
	res := network(t)
	if _, err := res.Journal.AddClient(res.WorkingKey, ClientParams{ID: "vasya"}, ""); err != nil {
		t.Fatalf("клиент: %v", err)
	}

	// Пустой собеседник: ему причитается всё.
	missing, err := res.Journal.Since(map[oplog.KeyID]uint64{})
	if err != nil {
		t.Fatalf("выборка: %v", err)
	}
	if len(missing) != res.Journal.Len() {
		t.Fatalf("к отправке %d записей из %d", len(missing), res.Journal.Len())
	}

	// Собеседнику, знающему всё, отдавать нечего.
	nothing, err := res.Journal.Since(res.Journal.Counters())
	if err != nil {
		t.Fatalf("выборка: %v", err)
	}
	if len(nothing) != 0 {
		t.Fatalf("знающему всё отдаём %d записей", len(nothing))
	}

	// Приём: копия журнала вливает то же самое и не спотыкается на повторах.
	raw, err := res.Journal.Bytes()
	if err != nil {
		t.Fatalf("выгрузка: %v", err)
	}
	copyOf, err := Read(bytesReader(raw))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	n, err := copyOf.Import(bytesReader(raw))
	if err != nil {
		t.Fatalf("повторный приём: %v", err)
	}
	if n != 0 {
		t.Fatalf("принято %d записей, а все они уже были", n)
	}
}

// Разносить нечего, пока в сети нет узлов, — и это отдельная ошибка, а не «связи нет».
func TestPushWithoutNodes(t *testing.T) {
	res := created(t, "")

	_, err := res.Journal.Push(t.Context(), res.WorkingKey, nil)
	if err == nil {
		t.Fatal("разнос по сети без узлов прошёл успешно")
	}
	_ = time.Now
}
