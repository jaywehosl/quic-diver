package oplog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Тела операций.
//
// Клиенты и узлы опознаются ключевой парой, а не общим секретом. Узел хранит только публичную
// часть, поэтому взлом узла не даёт возможности выдать себя за клиента: подделать подпись
// по публичному ключу нельзя. Общий секрет вроде токена-строки дал бы ровно обратное — один
// вскрытый узел выдал бы секреты всех, кто через него ходил.
//
// Тело кодируется JSON: подпись покрывает конкретные байты (см. op.go), поэтому неканоничность
// JSON безвредна, а расширять состав полей можно без ломки старых узлов.

// PublicKey — публичный ключ Ed25519 в теле операции.
type PublicKey []byte

func (p PublicKey) valid() bool { return len(p) == ed25519.PublicKeySize }

// AdminKey — ключ администратора и то, что ему позволено.
type AdminKey struct {
	PublicKey PublicKey `json:"public_key"`
	Scope     Scope     `json:"scope"`
	Label     string    `json:"label,omitempty"`
}

func (a AdminKey) validate() error {
	if !a.PublicKey.valid() {
		return fmt.Errorf("публичный ключ администратора должен быть %d байт", ed25519.PublicKeySize)
	}
	if !a.Scope.Valid() {
		return fmt.Errorf("неизвестная область прав %d", uint8(a.Scope))
	}
	return nil
}

// ID возвращает идентификатор ключа администратора.
func (a AdminKey) ID() KeyID { return KeyIDOf(ed25519.PublicKey(a.PublicKey)) }

// Genesis — первая запись сети. Задаёт её имя и владельцев.
//
// Хеш этой записи и есть отпечаток сети: он лежит в конфиге каждого узла, и по нему узел
// отличает свой журнал от чужого. Подписывается собственным ключом одного из владельцев —
// доверие к генезису берётся не из подписи, а из того, что его отпечаток занесён в конфиг руками.
type Genesis struct {
	Network string     `json:"network"`
	Owners  []AdminKey `json:"owners"`
}

func (g Genesis) validate() error {
	if strings.TrimSpace(g.Network) == "" {
		return fmt.Errorf("имя сети пустое")
	}
	if len(g.Owners) < 2 {
		// Решение 001: владельцев с самого начала двое, второй ключ офлайн. Потеря
		// единственного ключа означала бы потерю управления сетью навсегда.
		return fmt.Errorf("владельцев должно быть не меньше двух, задано %d", len(g.Owners))
	}
	seen := make(map[KeyID]struct{}, len(g.Owners))
	for i, o := range g.Owners {
		if err := o.validate(); err != nil {
			return fmt.Errorf("владелец %d: %w", i, err)
		}
		if o.Scope != ScopeOwner {
			return fmt.Errorf("владелец %d: область прав должна быть owner, задана %s", i, o.Scope)
		}
		if _, dup := seen[o.ID()]; dup {
			return fmt.Errorf("владелец %d: ключ %s повторяется", i, o.ID())
		}
		seen[o.ID()] = struct{}{}
	}
	return nil
}

// AdminAdd выдаёт ключу права.
type AdminAdd struct {
	Key AdminKey `json:"key"`
}

func (a AdminAdd) validate() error { return a.Key.validate() }

// AdminRevoke отзывает права у ключа.
type AdminRevoke struct {
	KeyID KeyID `json:"key_id"`
}

func (a AdminRevoke) validate() error {
	if a.KeyID.IsZero() {
		return fmt.Errorf("не указан отзываемый ключ")
	}
	return nil
}

// Limits — лимиты клиента. Ноль везде означает «без ограничения»: это удобнее, чем заводить
// отдельный признак, и совпадает с нулевым значением структуры.
//
// Лимиты по решению 001 мягкие: при разъехавшихся узлах возможно кратковременное превышение,
// и недоступность соседей никогда не повод отказать человеку.
type Limits struct {
	// Devices — сколько разных устройств могут работать одновременно.
	Devices int `json:"devices,omitempty"`
	// Addrs — сколько разных адресов клиента допускается одновременно.
	Addrs int `json:"addrs,omitempty"`
	// TrafficBytes — потолок трафика за период.
	TrafficBytes int64 `json:"traffic_bytes,omitempty"`
	// TrafficPeriod — как часто обнуляется счётчик трафика: "monthly", "weekly", "daily".
	// Пусто — счётчик не обнуляется вовсе.
	TrafficPeriod string `json:"traffic_period,omitempty"`
}

func (l Limits) validate() error {
	if l.Devices < 0 || l.Addrs < 0 || l.TrafficBytes < 0 {
		return fmt.Errorf("лимиты не могут быть отрицательными")
	}
	switch l.TrafficPeriod {
	case "", "daily", "weekly", "monthly":
	default:
		return fmt.Errorf("неизвестный период сброса трафика %q", l.TrafficPeriod)
	}
	if l.TrafficPeriod != "" && l.TrafficBytes == 0 {
		return fmt.Errorf("период сброса задан, а лимита трафика нет")
	}
	return nil
}

// Client — учётная запись человека.
type Client struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
	// PublicKey — чем клиент доказывает, кто он. Приватная часть уезжает в URI-бандл и
	// у узлов её нет.
	PublicKey PublicKey  `json:"public_key"`
	Limits    Limits     `json:"limits"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Suspended приостанавливает клиента, не удаляя его: перевыпуск и разбирательство
	// возможны без потери истории.
	Suspended bool `json:"suspended,omitempty"`
}

func (c Client) validate() error {
	if err := validID(c.ID); err != nil {
		return fmt.Errorf("идентификатор клиента: %w", err)
	}
	if !c.PublicKey.valid() {
		return fmt.Errorf("публичный ключ клиента должен быть %d байт", ed25519.PublicKeySize)
	}
	return c.Limits.validate()
}

// ClientRevoke убирает клиента из сети. Ключ после этого мёртв: перевыпуск — это новая пара.
type ClientRevoke struct {
	ID string `json:"id"`
}

func (c ClientRevoke) validate() error { return validID(c.ID) }

// Роли узла.
const (
	RoleIngress = "ingress"
	RoleEgress  = "egress"
)

// Node — узел сети.
//
// Роль живёт здесь, а не в конфиге на машине: по решению 001 узел узнаёт её из журнала,
// поэтому роль меняется на лету и без потери сессий.
//
// Роль — единственное, что участвует в маршрутизации. Никаких стран, площадок и прочих
// признаков у узла нет: сеть сама балансируется гонкой, и следить за конкретным узлом
// незачем. Куда какой узел ставить, решает администратор, когда назначает роль.
type Node struct {
	ID        string    `json:"id"`
	PublicKey PublicKey `json:"public_key"`
	// Roles — ingress, egress или обе сразу.
	Roles []string `json:"roles"`
	// Tags — свободные подписи для человека: по ним ищут узел в списке. На маршрутизацию
	// не влияют никак, и содержимое их произвольно.
	Tags []string `json:"tags,omitempty"`
	// Domain — имя, по которому узел предъявляет сертификат и к которому идут клиенты.
	Domain string `json:"domain"`
	// Endpoints — адреса вида host:port. Клиенту нужны литералы, чтобы поднять исключения
	// маршрутизации до включения туннеля.
	Endpoints []string `json:"endpoints"`
}

func (n Node) validate() error {
	if err := validID(n.ID); err != nil {
		return fmt.Errorf("идентификатор узла: %w", err)
	}
	if !n.PublicKey.valid() {
		return fmt.Errorf("публичный ключ узла должен быть %d байт", ed25519.PublicKeySize)
	}
	if len(n.Roles) == 0 {
		return fmt.Errorf("у узла %s нет ни одной роли", n.ID)
	}
	for _, r := range n.Roles {
		if r != RoleIngress && r != RoleEgress {
			return fmt.Errorf("неизвестная роль %q", r)
		}
	}
	if strings.TrimSpace(n.Domain) == "" {
		return fmt.Errorf("у узла %s не задано имя", n.ID)
	}
	if len(n.Endpoints) == 0 {
		return fmt.Errorf("у узла %s нет ни одного адреса", n.ID)
	}
	return nil
}

// HasRole сообщает, несёт ли узел указанную роль.
func (n Node) HasRole(role string) bool {
	for _, r := range n.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// NodeRevoke выводит узел из сети.
type NodeRevoke struct {
	ID string `json:"id"`
}

func (n NodeRevoke) validate() error { return validID(n.ID) }

// Routing — правила маршрутизации целиком, одной записью.
//
// Правила заменяются целиком, а не по одному: так снапшот всегда согласован, а разъехавшиеся
// узлы не собирают у себя половинки двух разных версий набора.
type Routing struct {
	Rules []Rule `json:"rules"`
}

// Rule — одно правило. Match — выражение в формате v2fly (geosite:…, geoip:…, domain:…),
// Action — что делать с потоком.
type Rule struct {
	Match   []string `json:"match"`
	Action  string   `json:"action"`
	Comment string   `json:"comment,omitempty"`
}

// Действия правил.
//
// Их ровно три, и параметров у них нет. Поток либо выходит наружу там, куда клиент
// подключился, либо уходит на выходной узел, либо не идёт никуда. Выбирать, какой именно
// выходной, не требуется: их выбирает гонка, а где они стоят — забота администратора,
// решённая ещё при назначении ролей.
const (
	// ActionDirect — выпустить наружу на том узле, к которому подключён клиент.
	ActionDirect = "direct"
	// ActionEgress — гнать через выходной узел.
	ActionEgress = "egress"
	// ActionBlock — оборвать: RST для TCP, NXDOMAIN на этапе имени.
	ActionBlock = "block"
)

func (r Routing) validate() error {
	for i, rule := range r.Rules {
		if len(rule.Match) == 0 {
			return fmt.Errorf("правило %d: пустое условие", i)
		}
		switch rule.Action {
		case ActionDirect, ActionEgress, ActionBlock:
		default:
			return fmt.Errorf("правило %d: неизвестное действие %q", i, rule.Action)
		}
	}
	return nil
}

// Settings — параметры сети, общие для всех узлов и клиентов.
type Settings struct {
	// BrutalUpMbps и BrutalDownMbps — потолок BRUTAL на участке клиент↔узел. Числа разные:
	// у домашнего канала отдача заметно уже приёма, и один общий потолок означал бы либо
	// недобор вниз, либо избыток вверх. Клиент применяет up к своей отправке, узел — down
	// к своей.
	//
	// Ноль означает обычный Cubic. Решение 006: алгоритм не снижает скорость при потерях,
	// поэтому число обязано соответствовать реальному каналу, и ставит его человек.
	BrutalUpMbps   int `json:"brutal_up_mbps,omitempty"`
	BrutalDownMbps int `json:"brutal_down_mbps,omitempty"`
	// BrutalMeshMbps — потолок на участке узел↔узел. Отдельное число, потому что это
	// совсем другой канал: между машинами в датацентрах, а не домашняя линия.
	BrutalMeshMbps int `json:"brutal_mesh_mbps,omitempty"`

	// DNSPrimary и DNSSecondary — резолверы, которыми узел разрешает имена.
	DNSPrimary   string `json:"dns_primary,omitempty"`
	DNSSecondary string `json:"dns_secondary,omitempty"`
	// DNSCacheEntries — потолок числа записей в кеше.
	DNSCacheEntries int `json:"dns_cache_entries,omitempty"`
	// DNSMinTTL и DNSMaxTTL переопределяют время жизни, пришедшее от авторитативных серверов.
	DNSMinTTL int `json:"dns_min_ttl,omitempty"`
	DNSMaxTTL int `json:"dns_max_ttl,omitempty"`
	// DNSFlushAt — метка мягкого сброса кеша имён, в секундах эпохи.
	//
	// Не команда, а состояние: узел, увидевший метку новее применённой, чистит кеш и
	// запоминает её. Так сброс расходится по сети сам и работает на узлах, которых в момент
	// команды не было в живых, — а команда, посланная по сети, до них бы не добралась.
	DNSFlushAt int64 `json:"dns_flush_at,omitempty"`
}

func (s Settings) validate() error {
	if s.BrutalUpMbps < 0 || s.BrutalDownMbps < 0 || s.BrutalMeshMbps < 0 {
		return fmt.Errorf("потолок скорости не может быть отрицательным")
	}
	if s.DNSCacheEntries < 0 {
		return fmt.Errorf("размер кеша не может быть отрицательным")
	}
	if s.DNSMinTTL < 0 || s.DNSMaxTTL < 0 {
		return fmt.Errorf("границы TTL не могут быть отрицательными")
	}
	if s.DNSMinTTL != 0 && s.DNSMaxTTL != 0 && s.DNSMinTTL > s.DNSMaxTTL {
		return fmt.Errorf("нижняя граница TTL больше верхней: %d > %d", s.DNSMinTTL, s.DNSMaxTTL)
	}
	return nil
}

// validID проверяет идентификаторы клиентов и узлов: они попадают в журнал, в логи и в имена,
// поэтому держим их узкими намеренно.
func validID(id string) error {
	if id == "" {
		return fmt.Errorf("пустой")
	}
	if len(id) > 64 {
		return fmt.Errorf("длиннее 64 символов")
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("недопустимый символ %q", r)
		}
	}
	return nil
}

// payloadFor разбирает тело операции в структуру, соответствующую её виду.
func payloadFor(kind Kind) (any, bool) {
	switch kind {
	case KindGenesis:
		return &Genesis{}, true
	case KindAdminAdd:
		return &AdminAdd{}, true
	case KindAdminRevoke:
		return &AdminRevoke{}, true
	case KindClientAdd, KindClientUpdate:
		return &Client{}, true
	case KindClientRevoke:
		return &ClientRevoke{}, true
	case KindNodeAdd, KindNodeUpdate:
		return &Node{}, true
	case KindNodeRevoke:
		return &NodeRevoke{}, true
	case KindRoutingSet:
		return &Routing{}, true
	case KindSettingsSet:
		return &Settings{}, true
	default:
		return nil, false
	}
}

type validator interface{ validate() error }

// DecodePayload разбирает и проверяет тело операции.
//
// Возвращает указатель на структуру нужного вида — вызывающему остаётся привести его к типу,
// который он ждёт по виду операции.
func DecodePayload(o *Op) (any, error) {
	v, ok := payloadFor(o.Kind)
	if !ok {
		return nil, fmt.Errorf("oplog: тело операции вида %s разобрать нечем", o.Kind)
	}
	dec := json.NewDecoder(bytes.NewReader(o.Payload))
	// Незнакомое поле — это либо запись от более новой версии, либо опечатка. И то и другое
	// должно быть громким: тихо применённая наполовину понятая операция хуже отказа.
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return nil, fmt.Errorf("oplog: разбор тела %s: %w", o.Kind, err)
	}
	if err := v.(validator).validate(); err != nil {
		return nil, fmt.Errorf("oplog: тело %s не проходит проверку: %w", o.Kind, err)
	}
	return v, nil
}

// NewOp собирает и подписывает операцию с телом.
func NewOp(s Signer, kind Kind, counter uint64, at time.Time, payload any) (*Op, error) {
	if v, ok := payload.(validator); ok {
		if err := v.validate(); err != nil {
			return nil, fmt.Errorf("oplog: тело %s не проходит проверку: %w", kind, err)
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("oplog: кодирование тела %s: %w", kind, err)
	}
	op := &Op{Kind: kind, Counter: counter, Time: at, Payload: body}
	if err := op.Sign(s); err != nil {
		return nil, err
	}
	return op, nil
}
