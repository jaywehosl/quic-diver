package fakeip

import (
	"net/netip"
	"testing"
	"time"
)

// Настоящие адреса имени ложатся рядом с подменным и достаются по нему.
//
// Без этого правила `geoip:` не работают вовсе: у потока к подменному адресу настоящего нет, а
// 198.18.0.0/15 не входит ни в одну страну — условие по подсети не совпадает никогда.
func TestRealAddrsTravelWithTheFakeOne(t *testing.T) {
	p := pool(t, "198.18.0.0/24", time.Hour)

	fake, err := p.Assign("yandex.ru")
	if err != nil {
		t.Fatalf("подменный адрес: %v", err)
	}
	if got := p.Real(fake); len(got) != 0 {
		t.Fatalf("адреса взялись из ниоткуда: %v", got)
	}

	real := []netip.Addr{
		netip.MustParseAddr("77.88.55.77"),
		netip.MustParseAddr("5.255.255.242"),
	}
	p.SetReal("yandex.ru", real)

	got := p.Real(fake)
	if len(got) != 2 || got[0] != real[0] {
		t.Fatalf("настоящие адреса не вернулись: %v", got)
	}
}

// Имя приводится к общему виду и здесь: «Yandex.RU.» и «yandex.ru» — одно и то же.
func TestSetRealNormalizesName(t *testing.T) {
	p := pool(t, "198.18.0.0/24", time.Hour)

	fake, err := p.Assign("yandex.ru")
	if err != nil {
		t.Fatalf("подменный адрес: %v", err)
	}
	p.SetReal("Yandex.RU.", []netip.Addr{netip.MustParseAddr("77.88.55.77")})

	if got := p.Real(fake); len(got) != 1 {
		t.Fatalf("имя с точкой и заглавными не нашлось: %v", got)
	}
}

// Чужой адрес ничего не знает: спрашивать о нём — не ошибка, но и ответа нет.
func TestRealOfUnknownAddr(t *testing.T) {
	p := pool(t, "198.18.0.0/24", time.Hour)

	if got := p.Real(netip.MustParseAddr("8.8.8.8")); got != nil {
		t.Fatalf("у чужого адреса нашлись адреса: %v", got)
	}
	// Имя, которому не выдавали подменного адреса, запоминать нечем — и это не отказ.
	p.SetReal("neverseen.example", []netip.Addr{netip.MustParseAddr("1.2.3.4")})
}
