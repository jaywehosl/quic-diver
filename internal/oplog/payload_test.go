package oplog

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testPubKey(t *testing.T) PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}
	return PublicKey(pub)
}

func TestGenesisNeedsTwoOwners(t *testing.T) {
	s := mustSigner(t)
	one := Genesis{
		Network: "qdiver",
		Owners:  []AdminKey{{PublicKey: testPubKey(t), Scope: ScopeOwner}},
	}
	if _, err := NewOp(s, KindGenesis, 1, time.Now(), one); err == nil {
		t.Fatal("генезис с одним владельцем принят — потеря ключа обесточила бы сеть")
	}

	two := Genesis{
		Network: "qdiver",
		Owners: []AdminKey{
			{PublicKey: testPubKey(t), Scope: ScopeOwner, Label: "основной"},
			{PublicKey: testPubKey(t), Scope: ScopeOwner, Label: "запасной, офлайн"},
		},
	}
	if _, err := NewOp(s, KindGenesis, 1, time.Now(), two); err != nil {
		t.Fatalf("нормальный генезис отвергнут: %v", err)
	}
}

func TestGenesisRejectsDuplicateAndNonOwner(t *testing.T) {
	same := testPubKey(t)
	dup := Genesis{
		Network: "qdiver",
		Owners: []AdminKey{
			{PublicKey: same, Scope: ScopeOwner},
			{PublicKey: same, Scope: ScopeOwner},
		},
	}
	if err := dup.validate(); err == nil {
		t.Fatal("два одинаковых ключа сошли за двух владельцев")
	}

	weak := Genesis{
		Network: "qdiver",
		Owners: []AdminKey{
			{PublicKey: testPubKey(t), Scope: ScopeOwner},
			{PublicKey: testPubKey(t), Scope: ScopeOperator},
		},
	}
	if err := weak.validate(); err == nil {
		t.Fatal("оператор принят за владельца в генезисе")
	}
}

func TestPayloadRoundTrip(t *testing.T) {
	s := mustSigner(t)
	at := time.Now()

	client := Client{
		ID:        "vasya",
		Label:     "Вася, телефон",
		PublicKey: testPubKey(t),
		Limits:    Limits{Devices: 3, TrafficBytes: 100 << 30, TrafficPeriod: "monthly"},
	}
	op, err := NewOp(s, KindClientAdd, 1, at, client)
	if err != nil {
		t.Fatalf("сборка операции: %v", err)
	}

	got, err := DecodePayload(op)
	if err != nil {
		t.Fatalf("разбор тела: %v", err)
	}
	back, ok := got.(*Client)
	if !ok {
		t.Fatalf("разобралось не в клиента, а в %T", got)
	}
	if back.ID != client.ID || back.Limits != client.Limits {
		t.Fatalf("клиент разъехался: %+v против %+v", back, client)
	}
	if string(back.PublicKey) != string(client.PublicKey) {
		t.Fatal("публичный ключ разъехался")
	}
}

func TestDecodePayloadRejectsUnknownField(t *testing.T) {
	s := mustSigner(t)

	// Тело собираем из заведомо годного клиента и дописываем в него лишнее поле. Иначе
	// проверка соскользнула бы: тело отвергалось бы за негодный ключ, а не за незнакомое
	// поле, и тест зеленел бы, ничего не проверяя.
	body, err := json.Marshal(Client{ID: "vasya", PublicKey: testPubKey(t)})
	if err != nil {
		t.Fatalf("кодирование: %v", err)
	}
	withExtra := strings.TrimSuffix(string(body), "}") + `,"новое_поле":1}`

	// Убеждаемся, что исходное тело проходит: значит отказ ниже вызван именно добавкой.
	base := &Op{Kind: KindClientAdd, Counter: 1, Time: time.Now(), Payload: body}
	if err := base.Sign(s); err != nil {
		t.Fatalf("подпись: %v", err)
	}
	if _, err := DecodePayload(base); err != nil {
		t.Fatalf("годное тело отвергнуто, тест ничего бы не проверил: %v", err)
	}

	// Так выглядит запись, пришедшая от соседа более новой версии.
	op := &Op{Kind: KindClientAdd, Counter: 2, Time: time.Now(), Payload: []byte(withExtra)}
	if err := op.Sign(s); err != nil {
		t.Fatalf("подпись: %v", err)
	}
	if _, err := DecodePayload(op); err == nil {
		t.Fatal("тело с незнакомым полем принято молча")
	}
}

func TestDecodePayloadRejectsInvalidBody(t *testing.T) {
	s := mustSigner(t)
	cases := map[string]any{
		"пустой идентификатор":    Client{ID: "", PublicKey: testPubKey(t)},
		"пробел в идентификаторе": Client{ID: "вася петров", PublicKey: testPubKey(t)},
		"короткий ключ":           Client{ID: "vasya", PublicKey: PublicKey("коротышка")},
		"отрицательный лимит":     Client{ID: "vasya", PublicKey: testPubKey(t), Limits: Limits{Devices: -1}},
		"период без лимита":       Client{ID: "vasya", PublicKey: testPubKey(t), Limits: Limits{TrafficPeriod: "monthly"}},
		"неизвестный период":      Client{ID: "vasya", PublicKey: testPubKey(t), Limits: Limits{TrafficBytes: 1, TrafficPeriod: "hourly"}},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewOp(s, KindClientAdd, 1, time.Now(), payload); err == nil {
				t.Fatal("негодное тело принято")
			}
		})
	}
}

func TestNodeValidation(t *testing.T) {
	good := Node{
		ID:        "warsaw-1",
		PublicKey: testPubKey(t),
		Roles:     []string{RoleEgress},
		Tags:      []string{"варшава", "толстый канал"},
		Domain:    "qdiver3.example.com",
		Endpoints: []string{"203.0.113.3:443", "[2001:db8::3]:443"},
	}
	if err := good.validate(); err != nil {
		t.Fatalf("нормальный узел отвергнут: %v", err)
	}
	if !good.HasRole(RoleEgress) || good.HasRole(RoleIngress) {
		t.Fatal("роли определяются неверно")
	}

	bad := good
	bad.Roles = []string{"вратарь"}
	if err := bad.validate(); err == nil {
		t.Fatal("выдуманная роль принята")
	}

	noAddr := good
	noAddr.Endpoints = nil
	if err := noAddr.validate(); err == nil {
		t.Fatal("узел без адресов принят — клиенту некуда ставить исключение маршрутизации")
	}
}

func TestRoutingValidation(t *testing.T) {
	ok := Routing{Rules: []Rule{
		{Match: []string{"geosite:category-ads-all"}, Action: ActionBlock},
		{Match: []string{"geosite:ru", "geoip:ru"}, Action: ActionDirect, Comment: "внутрь страны — со входного"},
		{Match: []string{"geosite:geolocation-!cn"}, Action: ActionEgress},
	}}
	if err := ok.validate(); err != nil {
		t.Fatalf("нормальные правила отвергнуты: %v", err)
	}

	// У правила ровно три исхода и ни одного параметра: наружу здесь, через выход или никуда.
	unknown := Routing{Rules: []Rule{{Match: []string{"geosite:netflix"}, Action: "через-варшаву"}}}
	if err := unknown.validate(); err == nil {
		t.Fatal("выдуманное действие принято")
	}

	empty := Routing{Rules: []Rule{{Action: ActionDirect}}}
	if err := empty.validate(); err == nil {
		t.Fatal("правило без условия принято")
	}
}

func TestSettingsValidation(t *testing.T) {
	if err := (Settings{DNSMinTTL: 600, DNSMaxTTL: 60}).validate(); err == nil {
		t.Fatal("нижняя граница TTL выше верхней — должно отвергаться")
	}
	if err := (Settings{BrutalUpMbps: -1}).validate(); err == nil {
		t.Fatal("отрицательный потолок принят")
	}
	good := Settings{
		BrutalUpMbps: 50, BrutalDownMbps: 200,
		DNSPrimary: "1.1.1.1:53", DNSCacheEntries: 4096,
		DNSMinTTL: 60, DNSMaxTTL: 3600,
	}
	if err := good.validate(); err != nil {
		t.Fatalf("нормальные настройки отвергнуты: %v", err)
	}
}

// Дамп журнала читают люди и он же уходит в бэкап: права и идентификаторы ключей должны
// быть словами, а не числами и массивами байтов.
func TestJSONIsHumanReadable(t *testing.T) {
	key := AdminKey{PublicKey: testPubKey(t), Scope: ScopeOperator, Label: "бот"}
	b, err := json.Marshal(AdminAdd{Key: key})
	if err != nil {
		t.Fatalf("кодирование: %v", err)
	}
	if !strings.Contains(string(b), `"scope":"operator"`) {
		t.Fatalf("область прав не словом: %s", b)
	}

	revoke := AdminRevoke{KeyID: KeyIDOf(ed25519.PublicKey(key.PublicKey))}
	rb, err := json.Marshal(revoke)
	if err != nil {
		t.Fatalf("кодирование: %v", err)
	}
	if !strings.Contains(string(rb), `"key_id":"`) {
		t.Fatalf("идентификатор ключа не строкой: %s", rb)
	}

	var back AdminRevoke
	if err := json.Unmarshal(rb, &back); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if back.KeyID != revoke.KeyID {
		t.Fatal("идентификатор ключа не пережил round-trip")
	}
}

func TestUnknownScopeIsNotSerialisable(t *testing.T) {
	if _, err := json.Marshal(AdminKey{PublicKey: testPubKey(t), Scope: Scope(9)}); err == nil {
		t.Fatal("ключ с неизвестными правами закодирован")
	}
}
