// Package ledger — динамическая база сети: кто сейчас подключён и сколько потрачено.
//
// В отличие от журнала (`internal/oplog`), тут ничего не подписывается и ничего не хранится
// на диске. Это картина «прямо сейчас», собранная из того, что узлы рассказали друг другу, и
// после перезапуска она собирается заново. Решение 001 §2.
//
// # Почему счётчик только растёт
//
// Трафик считается как G-Counter: у каждого узла своя ячейка по каждому клиенту, чужие ячейки
// он только принимает, свою только увеличивает. Слияние — поэлементный максимум, итог — сумма
// по узлам. Ни блокировок, ни конфликтов: при разделении сети цифры отстают и потом сходятся
// сами.
//
// # Почему лимиты мягкие
//
// Пока узлы не обменялись событиями, возможно кратковременное превышение — окно порядка
// десяти секунд. Это записано честно и осознанно, потому что правило, которое нельзя
// нарушать, другое: **недоступность соседей никогда не отказ клиенту.**
package ledger

import (
	"fmt"
	"maps"
	"sync"
	"time"
)

// sessionTTL — сколько событие о сессии считается живым без подтверждения.
//
// Узел, ушедший молча, перестаёт удерживать чужой лимит устройств через это время. Слишком
// короткий срок дал бы мигание при задержке gossip, слишком длинный — держал бы лимит за
// давно ушедшим клиентом.
const sessionTTL = 90 * time.Second

// Usage — сколько байт прошло через узел для одного клиента.
type Usage struct {
	Sent     uint64 `json:"sent"`
	Received uint64 `json:"received"`
}

// Total — сколько всего.
func (u Usage) Total() uint64 { return u.Sent + u.Received }

func (u Usage) merge(other Usage) Usage {
	// Максимум, а не сумма: это одна и та же ячейка, увиденная в разное время.
	return Usage{Sent: max(u.Sent, other.Sent), Received: max(u.Received, other.Received)}
}

// Session — устройство клиента, работающее прямо сейчас.
type Session struct {
	// Client — чьё устройство.
	Client string `json:"client"`
	// Device — чем устройство себя называет. Пустое означает, что клиент не назвался.
	Device string `json:"device"`
	// Addr — с какого адреса пришло.
	Addr string `json:"addr"`
	// Node — узел, который его обслуживает.
	Node string `json:"node"`
	// Conn — метка соединения. Одно устройство держит их несколько сразу.
	Conn string `json:"conn"`
	// Seen — когда узел в последний раз подтверждал, что сессия жива.
	Seen time.Time `json:"seen"`
}

// key — ячейка счётчика: клиент в конкретном расчётном периоде.
//
// Период входит в ключ затем, что счётчик, который только растёт, обнулить нельзя. Смена
// периода — это переход к новой ячейке, а старая просто перестаёт учитываться.
type key struct {
	client string
	period string
}

// sessionKey — одно соединение клиента на конкретном узле.
//
// Ключ по соединению, а не по устройству: одно устройство держит несколько соединений сразу
// — гонка рукопожатий оставляет по одному на каждый адрес каждого входного узла. С ключом по
// устройству уход любого из них стирал бы запись, поставленную другим, и человек исчезал бы
// из сети, продолжая в ней работать.
//
// Устройства при этом считаются по именам: см. Devices.
type sessionKey struct {
	client string
	conn   string
	node   string
}

// Ledger — состояние сети в памяти.
type Ledger struct {
	self string
	now  func() time.Time

	mu       sync.RWMutex
	traffic  map[key]map[string]Usage // ячейка → узел → сколько
	sessions map[sessionKey]Session
}

// Config — что нужно журналу событий.
type Config struct {
	// Self — имя своего узла. Своя ячейка счётчика — единственная, которую мы пишем.
	Self string
	// Now подменяет часы в тестах.
	Now func() time.Time
}

// New собирает журнал событий.
func New(cfg Config) *Ledger {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Ledger{
		self:     cfg.Self,
		now:      cfg.Now,
		traffic:  make(map[key]map[string]Usage),
		sessions: make(map[sessionKey]Session),
	}
}

// Add увеличивает наш счётчик клиента.
//
// period — расчётный период из лимитов клиента (см. PeriodOf). Пустой означает, что счётчик
// не обнуляется никогда.
func (l *Ledger) Add(client, period string, sent, received uint64) {
	if client == "" || (sent == 0 && received == 0) {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	k := key{client: client, period: period}
	cells, ok := l.traffic[k]
	if !ok {
		cells = make(map[string]Usage)
		l.traffic[k] = cells
	}
	u := cells[l.self]
	u.Sent += sent
	u.Received += received
	cells[l.self] = u
}

// Total — сколько клиент потратил за период по всей сети.
func (l *Ledger) Total(client, period string) Usage {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var sum Usage
	for node, u := range l.traffic[key{client: client, period: period}] {
		_ = node
		sum.Sent += u.Sent
		sum.Received += u.Received
	}
	return sum
}

// SessionUp отмечает, что устройство клиента работает на нашем узле.
//
// Зовётся после первого прикладного запроса, а не на попытку подключения: гонка рукопожатий
// оставляет по соединению на каждом входном узле, и отмечать их все значило бы, что клиент
// сам себе накрутил лимит устройств.
func (l *Ledger) SessionUp(client, device, addr, conn string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	k := sessionKey{client: client, conn: conn, node: l.self}
	l.sessions[k] = Session{
		Client: client, Device: device, Addr: addr, Node: l.self, Conn: conn, Seen: l.now(),
	}
}

// SessionDown убирает сессию сразу, не дожидаясь истечения срока.
func (l *Ledger) SessionDown(client, conn string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.sessions, sessionKey{client: client, conn: conn, node: l.self})
}

// Sessions перечисляет живые сессии клиента по всей сети.
func (l *Ledger) Sessions(client string) []Session {
	l.mu.RLock()
	defer l.mu.RUnlock()

	deadline := l.now().Add(-sessionTTL)
	var out []Session
	for k, s := range l.sessions {
		if k.client != client || s.Seen.Before(deadline) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Devices — сколько разных устройств клиента работает сейчас.
//
// Считаются именно устройства, а не соединения: одно устройство держит несколько соединений
// сразу и переподключается к другим узлам, и ни то ни другое не должно съедать лимит дважды.
//
// Безымянные устройства считаются по одному на соединение: назвать их нечем, а делать вид,
// что все они одно и то же, значило бы раздать безлимит любому, кто не сообщил имени.
func (l *Ledger) Devices(client string) int {
	named := make(map[string]struct{})
	unnamed := 0
	for _, s := range l.Sessions(client) {
		if s.Device == "" {
			unnamed++
			continue
		}
		named[s.Device] = struct{}{}
	}
	return len(named) + unnamed
}

// Addrs — с какого числа разных адресов клиент работает сейчас.
func (l *Ledger) Addrs(client string) int {
	seen := make(map[string]struct{})
	for _, s := range l.Sessions(client) {
		seen[s.Addr] = struct{}{}
	}
	return len(seen)
}

// Snapshot — что узел рассказывает соседям.
type Snapshot struct {
	// Traffic — наши и известные нам чужие ячейки: клиент|период → узел → сколько.
	Traffic map[string]map[string]Usage `json:"traffic"`
	// Sessions — живые сессии, известные нам.
	Sessions []Session `json:"sessions"`
}

// Own отдаёт только наши ячейки расхода.
//
// Нужны для слепка на диск: чужие ячейки приедут от соседей заново через несколько секунд
// после запуска, а наша не приедет ниоткуда — её знаем только мы.
func (l *Ledger) Own() []Cell {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var out []Cell
	for k, cells := range l.traffic {
		u, ok := cells[l.self]
		if !ok || (u.Sent == 0 && u.Received == 0) {
			continue
		}
		out = append(out, Cell{Client: k.client, Period: k.period, Usage: u})
	}
	return out
}

// Restore возвращает наши ячейки после перезапуска.
//
// Только увеличивает: если за время чтения слепка мы успели что-то посчитать, эти байты
// потерять нельзя. Счётчик не убывает — таково его определение.
func (l *Ledger) Restore(cells []Cell) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, c := range cells {
		k := key{client: c.Client, period: c.Period}
		byNode, ok := l.traffic[k]
		if !ok {
			byNode = make(map[string]Usage)
			l.traffic[k] = byNode
		}
		byNode[l.self] = byNode[l.self].merge(c.Usage)
	}
}

// Cell — ячейка расхода вместе с её адресом.
type Cell struct {
	Client string
	Period string
	Usage  Usage
}

// Snapshot собирает картину для соседей.
func (l *Ledger) Snapshot() Snapshot {
	l.mu.RLock()
	defer l.mu.RUnlock()

	snap := Snapshot{Traffic: make(map[string]map[string]Usage, len(l.traffic))}
	for k, cells := range l.traffic {
		snap.Traffic[encodeKey(k)] = maps.Clone(cells)
	}

	deadline := l.now().Add(-sessionTTL)
	for _, s := range l.sessions {
		if s.Seen.Before(deadline) {
			continue
		}
		snap.Sessions = append(snap.Sessions, s)
	}
	return snap
}

// Merge вливает картину соседа.
//
// Своя ячейка счётчика не трогается никогда: сосед мог узнать о ней раньше, чем мы её
// увеличили, и принять его значение означало бы потерять посчитанное.
func (l *Ledger) Merge(snap Snapshot) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for encoded, cells := range snap.Traffic {
		k, err := decodeKey(encoded)
		if err != nil {
			continue
		}
		ours, ok := l.traffic[k]
		if !ok {
			ours = make(map[string]Usage)
			l.traffic[k] = ours
		}
		for node, u := range cells {
			if node == l.self {
				continue
			}
			ours[node] = ours[node].merge(u)
		}
	}

	deadline := l.now().Add(-sessionTTL)
	for _, s := range snap.Sessions {
		if s.Node == l.self || s.Seen.Before(deadline) {
			// Про свои сессии сосед знать лучше нас не может.
			continue
		}
		k := sessionKey{client: s.Client, conn: s.Conn, node: s.Node}
		if prev, ok := l.sessions[k]; ok && !s.Seen.After(prev.Seen) {
			continue
		}
		l.sessions[k] = s
	}
}

// Sweep выбрасывает истёкшие сессии. Зовётся по таймеру.
func (l *Ledger) Sweep() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	deadline := l.now().Add(-sessionTTL)
	dropped := 0
	for k, s := range l.sessions {
		if s.Seen.Before(deadline) {
			delete(l.sessions, k)
			dropped++
		}
	}
	return dropped
}

// PeriodOf возвращает метку расчётного периода для момента времени.
//
// Пустая строка означает, что счётчик не обнуляется вовсе, — тогда и период один на всё
// время.
func PeriodOf(period string, at time.Time) string {
	at = at.UTC()
	switch period {
	case "daily":
		return at.Format("2006-01-02")
	case "weekly":
		year, week := at.ISOWeek()
		return fmt.Sprintf("%d-W%02d", year, week)
	case "monthly":
		return at.Format("2006-01")
	default:
		return ""
	}
}

func encodeKey(k key) string { return k.client + "\x00" + k.period }

func decodeKey(s string) (key, error) {
	for i := range len(s) {
		if s[i] == 0 {
			return key{client: s[:i], period: s[i+1:]}, nil
		}
	}
	return key{}, fmt.Errorf("ledger: негодный ключ %q", s)
}
