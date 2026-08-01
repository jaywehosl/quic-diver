package dnscache

import (
	"net/netip"
	"testing"
	"time"
)

func addrs(list ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(list))
	for _, s := range list {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// clock — управляемые часы: кеш живёт временем, и проверять его настоящим временем значит
// проверять терпение.
type clock struct{ t time.Time }

func newClock() *clock { return &clock{t: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time          { return c.t }
func (c *clock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func TestCacheRemembersAndForgets(t *testing.T) {
	c := newClock()
	cache := NewCache(Options{MaxEntries: 10, Now: c.Now})

	cache.Put("example.com", "ip4", addrs("93.184.215.14"), time.Minute)

	got, ok := cache.Get("example.com", "ip4")
	if !ok || len(got) != 1 || got[0].String() != "93.184.215.14" {
		t.Fatalf("ответ не вернулся: %v %v", got, ok)
	}

	// Другое семейство — другая запись.
	if _, ok := cache.Get("example.com", "ip6"); ok {
		t.Fatal("ответ для ip4 отдался как ip6")
	}

	c.Advance(time.Minute + time.Second)
	if _, ok := cache.Get("example.com", "ip4"); ok {
		t.Fatal("протухший ответ всё ещё отдаётся")
	}
}

// Время жизни зажимается настройками: и снизу, и сверху.
func TestCacheClampsTTL(t *testing.T) {
	c := newClock()
	cache := NewCache(Options{
		MaxEntries: 10,
		MinTTL:     30 * time.Second,
		MaxTTL:     10 * time.Minute,
		Now:        c.Now,
	})

	// Секунда снизу превращается в тридцать.
	cache.Put("short.example", "ip4", addrs("192.0.2.1"), time.Second)
	c.Advance(20 * time.Second)
	if _, ok := cache.Get("short.example", "ip4"); !ok {
		t.Fatal("нижняя граница не сработала: ответ протух раньше срока")
	}

	// Неделя сверху превращается в десять минут.
	cache.Put("long.example", "ip4", addrs("192.0.2.2"), 7*24*time.Hour)
	c.Advance(11 * time.Minute)
	if _, ok := cache.Get("long.example", "ip4"); ok {
		t.Fatal("верхняя граница не сработала: ответ живёт дольше положенного")
	}
}

// Вытеснение идёт по давности обращения, а не записи.
func TestCacheEvictsLeastRecentlyUsed(t *testing.T) {
	cache := NewCache(Options{MaxEntries: 2, Now: newClock().Now})

	cache.Put("first.example", "ip4", addrs("192.0.2.1"), time.Hour)
	cache.Put("second.example", "ip4", addrs("192.0.2.2"), time.Hour)

	// Трогаем первое — теперь самое старое по обращению это второе.
	if _, ok := cache.Get("first.example", "ip4"); !ok {
		t.Fatal("первое имя потерялось")
	}

	cache.Put("third.example", "ip4", addrs("192.0.2.3"), time.Hour)

	if _, ok := cache.Get("second.example", "ip4"); ok {
		t.Fatal("вытеснено не то имя: второе должно было уйти")
	}
	if _, ok := cache.Get("first.example", "ip4"); !ok {
		t.Fatal("вытеснено не то имя: первое трогали недавно")
	}
	if s := cache.Stats(); s.Evictions != 1 {
		t.Fatalf("вытеснений: %d", s.Evictions)
	}
}

// Мягкий сброс: кеш пуст, всё остальное на месте.
func TestCacheFlush(t *testing.T) {
	cache := NewCache(Options{MaxEntries: 10, Now: newClock().Now})
	cache.Put("a.example", "ip4", addrs("192.0.2.1"), time.Hour)
	cache.Put("b.example", "ip4", addrs("192.0.2.2"), time.Hour)

	if n := cache.Flush(); n != 2 {
		t.Fatalf("выброшено записей: %d", n)
	}
	if _, ok := cache.Get("a.example", "ip4"); ok {
		t.Fatal("после сброса ответ всё ещё в кеше")
	}
	if s := cache.Stats(); s.Entries != 0 {
		t.Fatalf("после сброса осталось %d записей", s.Entries)
	}

	// Кеш продолжает работать.
	cache.Put("c.example", "ip4", addrs("192.0.2.3"), time.Hour)
	if _, ok := cache.Get("c.example", "ip4"); !ok {
		t.Fatal("после сброса кеш перестал запоминать")
	}
}

// Уменьшение потолка действует сразу, а не когда-нибудь потом.
func TestCacheShrinksOnConfigure(t *testing.T) {
	cache := NewCache(Options{MaxEntries: 10, Now: newClock().Now})
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		cache.Put(n+".example", "ip4", addrs("192.0.2.1"), time.Hour)
	}

	cache.Configure(Options{MaxEntries: 2})
	if s := cache.Stats(); s.Entries != 2 {
		t.Fatalf("после сужения осталось %d записей вместо 2", s.Entries)
	}
}

// Нулевой потолок означает, что кеша нет вовсе.
func TestCacheOffWhenZero(t *testing.T) {
	cache := NewCache(Options{MaxEntries: 0, Now: newClock().Now})
	cache.Put("a.example", "ip4", addrs("192.0.2.1"), time.Hour)
	if _, ok := cache.Get("a.example", "ip4"); ok {
		t.Fatal("выключенный кеш всё-таки запомнил ответ")
	}
}

// Пустой ответ не кешируется: имя, у которого адрес вот-вот появится, найдётся сразу.
func TestCacheIgnoresEmptyAnswers(t *testing.T) {
	cache := NewCache(Options{MaxEntries: 10, Now: newClock().Now})
	cache.Put("a.example", "ip4", nil, time.Hour)
	if s := cache.Stats(); s.Entries != 0 {
		t.Fatalf("пустой ответ попал в кеш: %d записей", s.Entries)
	}
}

// Возвращаемый срез — копия: испортив его, вызывающий не должен испортить кеш.
func TestCacheReturnsCopy(t *testing.T) {
	cache := NewCache(Options{MaxEntries: 10, Now: newClock().Now})
	cache.Put("a.example", "ip4", addrs("192.0.2.1", "192.0.2.2"), time.Hour)

	got, _ := cache.Get("a.example", "ip4")
	got[0] = netip.MustParseAddr("10.0.0.1")

	again, _ := cache.Get("a.example", "ip4")
	if again[0].String() != "192.0.2.1" {
		t.Fatalf("кеш испортился снаружи: %v", again)
	}
}
