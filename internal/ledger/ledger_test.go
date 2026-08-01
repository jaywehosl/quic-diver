package ledger

import (
	"testing"
	"time"
)

type clock struct{ t time.Time }

func newClock() *clock { return &clock{t: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time          { return c.t }
func (c *clock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func TestTrafficCountsPerNode(t *testing.T) {
	c := newClock()
	l := New(Config{Self: "qdiver1", Now: c.Now})

	l.Add("vasya", "2026-07", 100, 900)
	l.Add("vasya", "2026-07", 50, 50)

	got := l.Total("vasya", "2026-07")
	if got.Sent != 150 || got.Received != 950 {
		t.Fatalf("свой счётчик: %+v", got)
	}
	if got.Total() != 1100 {
		t.Fatalf("сумма: %d", got.Total())
	}
}

// Периоды считаются порознь: это и есть обнуление счётчика, который убывать не умеет.
func TestTrafficSeparatedByPeriod(t *testing.T) {
	l := New(Config{Self: "qdiver1", Now: newClock().Now})

	l.Add("vasya", "2026-07", 100, 100)
	l.Add("vasya", "2026-08", 5, 5)

	if july := l.Total("vasya", "2026-07"); july.Total() != 200 {
		t.Fatalf("июль: %+v", july)
	}
	if august := l.Total("vasya", "2026-08"); august.Total() != 10 {
		t.Fatalf("август: %+v", august)
	}
}

// Итог по сети — сумма ячеек всех узлов.
func TestTrafficSumsAcrossNodes(t *testing.T) {
	c := newClock()
	one := New(Config{Self: "qdiver1", Now: c.Now})
	two := New(Config{Self: "qdiver3", Now: c.Now})

	one.Add("vasya", "2026-07", 100, 200)
	two.Add("vasya", "2026-07", 10, 20)

	one.Merge(two.Snapshot())
	got := one.Total("vasya", "2026-07")
	if got.Sent != 110 || got.Received != 220 {
		t.Fatalf("после слияния: %+v", got)
	}
}

// Своя ячейка чужой картиной не портится: сосед мог видеть её до того, как мы досчитали.
func TestMergeNeverOverwritesOwnCell(t *testing.T) {
	c := newClock()
	one := New(Config{Self: "qdiver1", Now: c.Now})
	two := New(Config{Self: "qdiver3", Now: c.Now})

	one.Add("vasya", "", 100, 100)
	two.Merge(one.Snapshot()) // сосед узнал про 100
	one.Add("vasya", "", 900, 900)
	one.Merge(two.Snapshot()) // а теперь рассказывает нам про наши же 100

	if got := one.Total("vasya", ""); got.Sent != 1000 {
		t.Fatalf("своя ячейка испортилась: %+v", got)
	}
}

// Слияние идемпотентно: та же картина, влитая дважды, ничего не удваивает.
func TestMergeIsIdempotent(t *testing.T) {
	c := newClock()
	one := New(Config{Self: "qdiver1", Now: c.Now})
	two := New(Config{Self: "qdiver3", Now: c.Now})

	two.Add("vasya", "", 10, 20)
	snap := two.Snapshot()

	one.Merge(snap)
	one.Merge(snap)
	one.Merge(snap)

	if got := one.Total("vasya", ""); got.Sent != 10 || got.Received != 20 {
		t.Fatalf("слияние удвоило: %+v", got)
	}
}

// Устройства считаются по устройствам, а не по соединениям.
func TestDevicesCountedOnce(t *testing.T) {
	c := newClock()
	one := New(Config{Self: "qdiver1", Now: c.Now})
	two := New(Config{Self: "qdiver3", Now: c.Now})

	one.SessionUp("vasya", "телефон", "203.0.113.1", "conn-телефон-203.0.113.1")
	two.SessionUp("vasya", "телефон", "203.0.113.1", "conn-телефон-203.0.113.1") // то же устройство, другой узел
	two.SessionUp("vasya", "ноутбук", "203.0.113.2", "conn-ноутбук-203.0.113.2")

	one.Merge(two.Snapshot())

	if n := one.Devices("vasya"); n != 2 {
		t.Fatalf("устройств: %d, а их два", n)
	}
	if n := one.Addrs("vasya"); n != 2 {
		t.Fatalf("адресов: %d", n)
	}
}

// Ушедший молча перестаёт держать лимит через отведённый срок.
func TestSessionsExpire(t *testing.T) {
	c := newClock()
	l := New(Config{Self: "qdiver1", Now: c.Now})

	l.SessionUp("vasya", "телефон", "203.0.113.1", "conn-телефон-203.0.113.1")
	if n := l.Devices("vasya"); n != 1 {
		t.Fatalf("устройств сразу: %d", n)
	}

	c.Advance(sessionTTL + time.Second)
	if n := l.Devices("vasya"); n != 0 {
		t.Fatalf("истёкшая сессия всё ещё держит лимит: %d", n)
	}
	if dropped := l.Sweep(); dropped != 1 {
		t.Fatalf("выметено: %d", dropped)
	}
}

// Отключение действует сразу, не дожидаясь срока.
func TestSessionDown(t *testing.T) {
	l := New(Config{Self: "qdiver1", Now: newClock().Now})
	l.SessionUp("vasya", "телефон", "203.0.113.1", "conn-телефон-203.0.113.1")
	l.SessionDown("vasya", "conn-телефон-203.0.113.1")

	if n := l.Devices("vasya"); n != 0 {
		t.Fatalf("сессия пережила отключение: %d", n)
	}
}

// Уход одного соединения не убирает другое, даже если устройство одно и то же.
//
// Поймано живой сетью: гонка рукопожатий здоровается по v4 и по v6, оба приветствия
// сходятся, и проигравший, закрываясь, стирал сессию победителя. Человек исчезал из сети,
// продолжая в ней работать.
func TestSessionDownTouchesOnlyItsOwnConnection(t *testing.T) {
	l := New(Config{Self: "qdiver1", Now: newClock().Now})

	l.SessionUp("vasya", "ноутбук", "203.0.113.1", "conn-v4")
	l.SessionUp("vasya", "ноутбук", "2001:db8::1", "conn-v6")

	// Одно устройство, два соединения — лимит занимает одно.
	if n := l.Devices("vasya"); n != 1 {
		t.Fatalf("устройств: %d, а оно одно на двух соединениях", n)
	}

	l.SessionDown("vasya", "conn-v6")

	if n := l.Devices("vasya"); n != 1 {
		t.Fatalf("уход одного соединения убрал устройство целиком: устройств %d", n)
	}
	if got := l.Sessions("vasya"); len(got) != 1 || got[0].Conn != "conn-v4" {
		t.Fatalf("осталось не то соединение: %+v", got)
	}
}

// Безымянные устройства считаются по одному на соединение: иначе тот, кто не назвался,
// получил бы безлимит.
func TestUnnamedDevicesCountedSeparately(t *testing.T) {
	l := New(Config{Self: "qdiver1", Now: newClock().Now})

	l.SessionUp("vasya", "", "203.0.113.1", "conn-1")
	l.SessionUp("vasya", "", "203.0.113.2", "conn-2")

	if n := l.Devices("vasya"); n != 2 {
		t.Fatalf("безымянных устройств насчитали %d вместо 2", n)
	}
}

// Про свои сессии сосед знать лучше нас не может.
func TestMergeIgnoresOurOwnSessions(t *testing.T) {
	c := newClock()
	one := New(Config{Self: "qdiver1", Now: c.Now})
	two := New(Config{Self: "qdiver3", Now: c.Now})

	one.SessionUp("vasya", "телефон", "203.0.113.1", "conn-телефон-203.0.113.1")
	two.Merge(one.Snapshot())

	one.SessionDown("vasya", "conn-телефон-203.0.113.1")
	// Сосед всё ещё думает, что сессия жива, и рассказывает нам об этом.
	one.Merge(two.Snapshot())

	if n := one.Devices("vasya"); n != 0 {
		t.Fatalf("сосед воскресил нашу же сессию: %d", n)
	}
}

// Истёкшие сессии по сети не разносятся.
func TestSnapshotSkipsStaleSessions(t *testing.T) {
	c := newClock()
	l := New(Config{Self: "qdiver1", Now: c.Now})
	l.SessionUp("vasya", "телефон", "203.0.113.1", "conn-телефон-203.0.113.1")

	c.Advance(sessionTTL + time.Second)
	if n := len(l.Snapshot().Sessions); n != 0 {
		t.Fatalf("в картине для соседей %d протухших сессий", n)
	}
}

func TestPeriodOf(t *testing.T) {
	at := time.Date(2026, 7, 31, 23, 0, 0, 0, time.UTC)
	cases := map[string]string{
		"daily":   "2026-07-31",
		"monthly": "2026-07",
		"weekly":  "2026-W31",
		"":        "",
		"чепуха":  "",
	}
	for period, want := range cases {
		if got := PeriodOf(period, at); got != want {
			t.Fatalf("период %q дал %q вместо %q", period, got, want)
		}
	}
}
