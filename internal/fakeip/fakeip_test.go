package fakeip

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func pool(t *testing.T, cidr string, lease time.Duration) *Pool {
	t.Helper()
	p, err := New(cidr, lease)
	if err != nil {
		t.Fatalf("создание пула: %v", err)
	}
	return p
}

func TestSameNameGetsSameAddress(t *testing.T) {
	p := pool(t, "198.18.0.0/24", time.Hour)

	first, err := p.Assign("example.com")
	if err != nil {
		t.Fatalf("выдача: %v", err)
	}
	second, err := p.Assign("EXAMPLE.COM.")
	if err != nil {
		t.Fatalf("повторная выдача: %v", err)
	}
	if first != second {
		t.Fatalf("одному имени выдано два адреса: %s и %s", first, second)
	}
	if p.Len() != 1 {
		t.Fatalf("занято адресов: %d", p.Len())
	}
}

func TestLookupReturnsName(t *testing.T) {
	p := pool(t, "198.18.0.0/24", time.Hour)

	addr, err := p.Assign("example.com")
	if err != nil {
		t.Fatalf("выдача: %v", err)
	}
	name, ok := p.Lookup(addr)
	if !ok || name != "example.com" {
		t.Fatalf("обратный поиск дал %q, %v", name, ok)
	}

	if _, ok := p.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("чужой адрес нашёлся в пуле")
	}
}

func TestDifferentNamesGetDifferentAddresses(t *testing.T) {
	p := pool(t, "198.18.0.0/24", time.Hour)

	seen := make(map[netip.Addr]string)
	for _, name := range []string{"a.com", "b.com", "c.com"} {
		addr, err := p.Assign(name)
		if err != nil {
			t.Fatalf("выдача %s: %v", name, err)
		}
		if prev, ok := seen[addr]; ok {
			t.Fatalf("адрес %s выдан и %s, и %s", addr, prev, name)
		}
		seen[addr] = name
	}
}

// Пока диапазон не исчерпан, ничего не переиспользуется.
func TestFreshAddressesFirst(t *testing.T) {
	p := pool(t, "198.18.0.0/28", time.Hour) // тринадцать пригодных адресов

	var addrs []netip.Addr
	for i := 0; i < 5; i++ {
		addr, err := p.Assign(string(rune('a'+i)) + ".com")
		if err != nil {
			t.Fatalf("выдача %d: %v", i, err)
		}
		addrs = append(addrs, addr)
	}
	for i := 1; i < len(addrs); i++ {
		if addrs[i].Compare(addrs[i-1]) <= 0 {
			t.Fatalf("адреса выдаются не по порядку: %v", addrs)
		}
	}
}

// fill забивает пул до отказа и возвращает выданные адреса по порядку.
//
// Ёмкость выясняется на месте, а не считается по маске: часть диапазона уходит под адрес
// сети, широковещательный и службу имён, и тест, знающий это число наизусть, ломался бы от
// любой правки резервирования.
func fill(t *testing.T, p *Pool, prefix string) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	for i := 0; i < 4096; i++ {
		addr, err := p.Assign(fmt.Sprintf("%s%d.com", prefix, i))
		if err != nil {
			return out
		}
		out = append(out, addr)
	}
	t.Fatal("пул не кончился — диапазон для теста слишком велик")
	return nil
}

// Отбирать адрес у имени, которым только что пользовались, нельзя: живое соединение уехало
// бы на чужой сайт.
func TestExhaustedPoolRefusesToStealFreshLease(t *testing.T) {
	p := pool(t, "198.18.0.0/29", time.Hour)

	filled := fill(t, p, "a")
	if len(filled) == 0 {
		t.Fatal("пул не выдал ни одного адреса")
	}

	_, err := p.Assign("свежий.com")
	if err == nil {
		t.Fatal("адрес отобран у свежей аренды")
	}
	if !strings.Contains(err.Error(), "исчерпан") {
		t.Fatalf("непонятная причина отказа: %v", err)
	}
}

// А вот пережившую свой срок аренду переиспользовать можно.
func TestStaleLeaseIsReused(t *testing.T) {
	p := pool(t, "198.18.0.0/29", time.Minute)

	now := time.Now()
	p.nowFunc = func() time.Time { return now }

	filled := fill(t, p, "a")
	oldest := filled[0]

	// Час спустя все аренды давно просрочены, и первой уходит самая старая.
	now = now.Add(time.Hour)
	reused, err := p.Assign("новый.com")
	if err != nil {
		t.Fatalf("выдача после истечения: %v", err)
	}
	if reused != oldest {
		t.Fatalf("переиспользован не самый старый адрес: %s против %s", reused, oldest)
	}
	if name, ok := p.Lookup(oldest); !ok || name != "новый.com" {
		t.Fatalf("адрес числится за %q (%v)", name, ok)
	}
}

// Обращение продлевает аренду: имя, которым пользуются, не должно вытесняться.
func TestLookupRefreshesLease(t *testing.T) {
	p := pool(t, "198.18.0.0/29", time.Minute)

	now := time.Now()
	p.nowFunc = func() time.Time { return now }

	filled := fill(t, p, "a")
	if len(filled) < 2 {
		t.Fatalf("для проверки нужно хотя бы два адреса, выдано %d", len(filled))
	}
	oldest, second := filled[0], filled[1]

	now = now.Add(30 * time.Second)
	p.Lookup(oldest) // им пользуются, вытеснять нельзя

	now = now.Add(40 * time.Second)
	reused, err := p.Assign("новый.com")
	if err != nil {
		t.Fatalf("выдача: %v", err)
	}
	if reused != second {
		t.Fatalf("вытеснили %s, а надо было %s — им не пользовались", reused, second)
	}
}

func TestContains(t *testing.T) {
	p := pool(t, "198.18.0.0/15", time.Hour)

	if !p.Contains(netip.MustParseAddr("198.18.5.5")) {
		t.Fatal("свой адрес не признан своим")
	}
	if p.Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("чужой адрес признан своим")
	}
	if p.Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("адрес v6 признан своим — пул только v4")
	}
}

func TestRejectsIPv6Range(t *testing.T) {
	if _, err := New("2001:db8::/32", time.Hour); err == nil {
		t.Fatal("диапазон v6 принят")
	}
}
