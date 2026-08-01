// Package dnscache — резолвер узла: первичный и вторичный адреса, кеш ответов.
//
// Узел разрешает имена постоянно: клиент присылает имя, а не адрес, и каждое соединение к
// сайту начинается с запроса. Без кеша один человек, открывший ленту новостей, устраивает
// сотню запросов к резолверу за секунду — все за одними и теми же адресами.
package dnscache

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

// Answer — то, что кеш помнит про имя.
type Answer struct {
	Addrs []netip.Addr
	// TTL — сколько ответ считается свежим, уже с учётом переопределения.
	TTL time.Duration
}

// key — имя вместе с семейством адресов: A и AAAA живут в кеше порознь.
type key struct {
	name    string
	network string
}

type entry struct {
	key     key
	addrs   []netip.Addr
	expires time.Time
	elem    *list.Element
}

// Cache — кеш ответов с ограничением по числу записей.
//
// Вытеснение по давности обращения, а не по времени записи: имя, к которому ходят каждую
// секунду, вытеснять бессмысленно, каким бы старым оно ни было.
type Cache struct {
	mu      sync.Mutex
	entries map[key]*entry
	order   *list.List // впереди — то, к чему обращались недавно

	maxEntries     int
	minTTL, maxTTL time.Duration
	now            func() time.Time

	hits, misses, evictions uint64
}

// Options — как настроить кеш.
type Options struct {
	// MaxEntries — потолок числа записей. Ноль означает, что кеш выключен вовсе.
	MaxEntries int
	// MinTTL и MaxTTL зажимают время жизни, пришедшее от авторитативных серверов.
	//
	// Нижняя граница спасает от имён с TTL в одну секунду, из-за которых кеш не работает.
	// Верхняя — от имён с TTL в неделю, из-за которых переезд сайта замечается через неделю.
	MinTTL, MaxTTL time.Duration
	// Now подменяет часы в тестах.
	Now func() time.Time
}

// NewCache собирает кеш.
func NewCache(o Options) *Cache {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Cache{
		entries:    make(map[key]*entry),
		order:      list.New(),
		maxEntries: o.MaxEntries,
		minTTL:     o.MinTTL,
		maxTTL:     o.MaxTTL,
		now:        o.Now,
	}
}

// Get отдаёт живой ответ, если он есть.
func (c *Cache) Get(name, network string) ([]netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	k := key{name: name, network: network}
	e, ok := c.entries[k]
	if !ok {
		c.misses++
		return nil, false
	}
	if !c.now().Before(e.expires) {
		// Протухший ответ не отдаём и не держим: место в кеше дороже.
		c.remove(e)
		c.misses++
		return nil, false
	}

	c.order.MoveToFront(e.elem)
	c.hits++
	// Копия: вызывающий волен делать со срезом что угодно, а запись живёт дальше.
	out := make([]netip.Addr, len(e.addrs))
	copy(out, e.addrs)
	return out, true
}

// Put запоминает ответ и возвращает время жизни, с которым тот лёг в кеш.
//
// Возвращает, а не молчит, затем что зажатое время — это то, что администратор увидит в
// журнале. Разница между «сервер сказал 7 секунд» и «в кеше лежит 30» — ровно то, ради чего
// настройка и заводилась, и человек должен видеть результат, а не намерение.
func (c *Cache) Put(name, network string, addrs []netip.Addr, ttl time.Duration) time.Duration {
	if len(addrs) == 0 {
		// Пустой ответ не кешируем: отрицательное кеширование — отдельная история, и без
		// неё имя, у которого адрес вот-вот появится, найдётся сразу.
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.maxEntries <= 0 {
		return 0
	}

	ttl = c.clamp(ttl)
	k := key{name: name, network: network}

	stored := make([]netip.Addr, len(addrs))
	copy(stored, addrs)

	if e, ok := c.entries[k]; ok {
		e.addrs = stored
		e.expires = c.now().Add(ttl)
		c.order.MoveToFront(e.elem)
		return ttl
	}

	e := &entry{key: k, addrs: stored, expires: c.now().Add(ttl)}
	e.elem = c.order.PushFront(e)
	c.entries[k] = e

	for len(c.entries) > c.maxEntries {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		c.remove(oldest.Value.(*entry))
		c.evictions++
	}
	return ttl
}

// clamp зажимает время жизни границами. Зовётся под блокировкой.
func (c *Cache) clamp(ttl time.Duration) time.Duration {
	if c.minTTL > 0 && ttl < c.minTTL {
		return c.minTTL
	}
	if c.maxTTL > 0 && ttl > c.maxTTL {
		return c.maxTTL
	}
	return ttl
}

func (c *Cache) remove(e *entry) {
	c.order.Remove(e.elem)
	delete(c.entries, e.key)
}

// Flush опустошает кеш, не трогая ничего больше.
//
// Тот самый мягкий сброс: узел продолжает работать, соединения не рвутся, следующий запрос
// просто идёт к резолверу заново.
func (c *Cache) Flush() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	n := len(c.entries)
	c.entries = make(map[key]*entry)
	c.order.Init()
	return n
}

// Configure меняет параметры на ходу.
//
// Уменьшение потолка вытесняет лишнее сразу же: настройка, которая начнёт действовать
// когда-нибудь потом, бесполезна тому, кто её меняет ради освобождения памяти.
func (c *Cache) Configure(o Options) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.maxEntries = o.MaxEntries
	c.minTTL = o.MinTTL
	c.maxTTL = o.MaxTTL

	if c.maxEntries <= 0 {
		c.entries = make(map[key]*entry)
		c.order.Init()
		return
	}
	for len(c.entries) > c.maxEntries {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		c.remove(oldest.Value.(*entry))
		c.evictions++
	}
}

// Stats — что кеш успел повидать.
type Stats struct {
	Entries    int
	MaxEntries int
	Hits       uint64
	Misses     uint64
	Evictions  uint64
}

func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{
		Entries:    len(c.entries),
		MaxEntries: c.maxEntries,
		Hits:       c.hits,
		Misses:     c.misses,
		Evictions:  c.evictions,
	}
}
