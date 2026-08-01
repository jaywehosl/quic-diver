package ledger

import (
	"testing"
	"time"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

func client(limits oplog.Limits) oplog.Client {
	return oplog.Client{ID: "vasya", Limits: limits}
}

func TestNoLimitsMeansAlwaysAllowed(t *testing.T) {
	c := newClock()
	l := New(Config{Self: "qdiver1", Now: c.Now})

	l.Add("vasya", "", 1<<40, 1<<40)
	l.SessionUp("vasya", "телефон", "203.0.113.1", "conn-телефон-203.0.113.1")

	if v := l.Check(client(oplog.Limits{}), "ноутбук", "203.0.113.9", c.Now()); !v.Allowed {
		t.Fatalf("без лимитов отказали: %s", v.Reason)
	}
}

func TestTrafficLimit(t *testing.T) {
	c := newClock()
	l := New(Config{Self: "qdiver1", Now: c.Now})
	limits := oplog.Limits{TrafficBytes: 1 << 30, TrafficPeriod: "monthly"}
	period := PeriodOf("monthly", c.Now())

	l.Add("vasya", period, 500<<20, 0)
	if v := l.Check(client(limits), "телефон", "203.0.113.1", c.Now()); !v.Allowed {
		t.Fatalf("на половине лимита отказали: %s", v.Reason)
	}

	l.Add("vasya", period, 600<<20, 0)
	v := l.Check(client(limits), "телефон", "203.0.113.1", c.Now())
	if v.Allowed {
		t.Fatal("лимит трафика перебран, а клиента пустили")
	}
	if v.Reason == "" {
		t.Fatal("отказ без объяснения")
	}
}

// Новый период — счётчик начинается заново, хотя старый никуда не делся.
func TestTrafficLimitResetsWithPeriod(t *testing.T) {
	c := newClock()
	l := New(Config{Self: "qdiver1", Now: c.Now})
	limits := oplog.Limits{TrafficBytes: 1 << 30, TrafficPeriod: "monthly"}

	l.Add("vasya", PeriodOf("monthly", c.Now()), 2<<30, 0)
	if l.Check(client(limits), "телефон", "203.0.113.1", c.Now()).Allowed {
		t.Fatal("лимит перебран, а пустили")
	}

	next := c.Now().AddDate(0, 1, 0)
	if v := l.Check(client(limits), "телефон", "203.0.113.1", next); !v.Allowed {
		t.Fatalf("в новом периоде отказали: %s", v.Reason)
	}
}

func TestDeviceLimit(t *testing.T) {
	c := newClock()
	l := New(Config{Self: "qdiver1", Now: c.Now})
	limits := oplog.Limits{Devices: 2}

	l.SessionUp("vasya", "телефон", "203.0.113.1", "conn-телефон-203.0.113.1")
	l.SessionUp("vasya", "ноутбук", "203.0.113.2", "conn-ноутбук-203.0.113.2")

	if v := l.Check(client(limits), "планшет", "203.0.113.3", c.Now()); v.Allowed {
		t.Fatal("третье устройство пустили при лимите в два")
	}
	// Уже работающее устройство лимита второй раз не занимает.
	if v := l.Check(client(limits), "телефон", "203.0.113.1", c.Now()); !v.Allowed {
		t.Fatalf("своему же устройству отказали: %s", v.Reason)
	}
}

func TestAddrLimit(t *testing.T) {
	c := newClock()
	l := New(Config{Self: "qdiver1", Now: c.Now})
	limits := oplog.Limits{Addrs: 1}

	l.SessionUp("vasya", "телефон", "203.0.113.1", "conn-телефон-203.0.113.1")

	if v := l.Check(client(limits), "ноутбук", "198.51.100.7", c.Now()); v.Allowed {
		t.Fatal("второй адрес пустили при лимите в один")
	}
	if v := l.Check(client(limits), "ноутбук", "203.0.113.1", c.Now()); !v.Allowed {
		t.Fatalf("с того же адреса отказали: %s", v.Reason)
	}
}

func TestSuspendedAndExpired(t *testing.T) {
	c := newClock()
	l := New(Config{Self: "qdiver1", Now: c.Now})

	suspended := client(oplog.Limits{})
	suspended.Suspended = true
	if l.Check(suspended, "телефон", "203.0.113.1", c.Now()).Allowed {
		t.Fatal("приостановленного клиента пустили")
	}

	past := c.Now().Add(-time.Hour)
	expired := client(oplog.Limits{})
	expired.ExpiresAt = &past
	if l.Check(expired, "телефон", "203.0.113.1", c.Now()).Allowed {
		t.Fatal("клиента с истёкшим сроком пустили")
	}

	future := c.Now().Add(time.Hour)
	fresh := client(oplog.Limits{})
	fresh.ExpiresAt = &future
	if v := l.Check(fresh, "телефон", "203.0.113.1", c.Now()); !v.Allowed {
		t.Fatalf("живому клиенту отказали: %s", v.Reason)
	}
}

// Лимит устройств считается по всей сети, а не по одному узлу.
func TestDeviceLimitSpansNetwork(t *testing.T) {
	c := newClock()
	one := New(Config{Self: "qdiver1", Now: c.Now})
	two := New(Config{Self: "qdiver3", Now: c.Now})

	two.SessionUp("vasya", "телефон", "203.0.113.1", "conn-телефон-203.0.113.1")
	two.SessionUp("vasya", "ноутбук", "203.0.113.2", "conn-ноутбук-203.0.113.2")
	one.Merge(two.Snapshot())

	if v := one.Check(client(oplog.Limits{Devices: 2}), "планшет", "203.0.113.3", c.Now()); v.Allowed {
		t.Fatal("устройства соседнего узла лимит не удержали")
	}
}

// Клиент, не назвавшийся устройством, лимитом устройств не режется: считать нечем, а
// отказывать из-за этого нельзя.
func TestUnnamedDevicePassesDeviceLimit(t *testing.T) {
	c := newClock()
	l := New(Config{Self: "qdiver1", Now: c.Now})
	l.SessionUp("vasya", "телефон", "203.0.113.1", "conn-телефон-203.0.113.1")
	l.SessionUp("vasya", "ноутбук", "203.0.113.2", "conn-ноутбук-203.0.113.2")

	if v := l.Check(client(oplog.Limits{Devices: 2}), "", "203.0.113.3", c.Now()); !v.Allowed {
		t.Fatalf("безымянному устройству отказали: %s", v.Reason)
	}
}
