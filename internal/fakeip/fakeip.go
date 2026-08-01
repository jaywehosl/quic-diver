// Package fakeip раздаёт подменные адреса именам.
//
// Из туннеля приходят пакеты, в которых имени нет. Чтобы правила по доменам работали, имя
// надо узнать раньше первого пакета — и единственное место, где это возможно, DNS-запрос.
// Клиент отвечает на него адресом из служебного диапазона и запоминает, кому его выдал.
// Дальше соединение на этот адрес однозначно указывает на имя.
//
// # Почему настоящий адрес не нужен
//
// Узлу отправляется имя, а не адрес: CONNECT несёт `example.com:443`, и разрешает имя сам
// узел. Отсюда два следствия. Во-первых, подменный адрес живёт только внутри клиента и
// наружу не попадает никогда. Во-вторых, имя, у которого есть только AAAA, открывается с
// машины без IPv6: приложение соединяется по подменному v4, а узел выходит по настоящему v6.
//
// # Срок аренды
//
// Аренда живёт заведомо дольше TTL, отданного приложению. Иначе адрес вернулся бы в пул,
// пока приложение его ещё помнит, и следующее соединение уехало бы на чужой домен — ошибка
// редкая, тихая и совершенно необъяснимая для того, кто её поймает.
package fakeip

import (
	"container/list"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// DefaultRange — диапазон подменных адресов.
//
// 198.18.0.0/15 отведён RFC 2544 под испытания оборудования и в настоящей сети не
// встречается. Брать что-то из частных диапазонов нельзя: они у людей заняты, и подменный
// адрес совпал бы с домашним роутером или рабочей сетью.
const DefaultRange = "198.18.0.0/15"

// DefaultLease — сколько держится аренда без обращений.
const DefaultLease = time.Hour

// Pool раздаёт адреса именам.
type Pool struct {
	mu      sync.Mutex
	prefix  netip.Prefix
	service netip.Addr
	next    netip.Addr
	last    netip.Addr
	lease   time.Duration
	byName  map[string]*entry
	byAddr  map[netip.Addr]*entry
	order   *list.List // порядок обращений, для вытеснения самых старых
	nowFunc func() time.Time
}

type entry struct {
	name string
	addr netip.Addr
	seen time.Time
	el   *list.Element
	// real — настоящие адреса имени, если их успели узнать.
	//
	// Нужны ровно для правил `geoip:`: у потока к подменному адресу настоящего адреса нет, а
	// без него условие по подсети не совпадает никогда — 198.18.0.0/15 не лежит ни в одной
	// стране. Имя при этом известно, поэтому `geosite:` работает и без этого поля.
	real []netip.Addr
}

// New создаёт пул.
func New(cidr string, lease time.Duration) (*Pool, error) {
	if cidr == "" {
		cidr = DefaultRange
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("fakeip: диапазон %q: %w", cidr, err)
	}
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("fakeip: диапазон должен быть v4, задан %s", cidr)
	}
	if lease <= 0 {
		lease = DefaultLease
	}

	prefix = prefix.Masked()
	// Крайние адреса диапазона не раздаём: первый — адрес сети, последний —
	// широковещательный, и хосту такой адрес не назначается. Подменные адреса живут только
	// внутри клиента, но интерфейс с ними поднимается настоящий, и его правила действуют.
	//
	// Следующий за адресом сети отходит службе имён. Посадить её на адрес самого интерфейса
	// нельзя: такой адрес ядро считает своим и обрабатывает пакеты само, до нашего стека они
	// не доходят вовсе — запрос упирается в «connection refused».
	service := prefix.Addr().Next()
	first := service.Next()
	last := lastAddr(prefix).Prev()
	if first.Compare(last) > 0 {
		return nil, fmt.Errorf("fakeip: в диапазоне %s не остаётся адресов для раздачи", cidr)
	}

	return &Pool{
		prefix:  prefix,
		service: service,
		next:    first,
		last:    last,
		lease:   lease,
		byName:  make(map[string]*entry),
		byAddr:  make(map[netip.Addr]*entry),
		order:   list.New(),
		nowFunc: time.Now,
	}, nil
}

// Prefix возвращает диапазон пула — его надо завернуть в туннель, иначе пакеты на
// подменные адреса не дойдут до стека.
func (p *Pool) Prefix() netip.Prefix { return p.prefix }

// ServiceAddr — адрес, на котором отвечает служба имён.
//
// Он лежит внутри диапазона, а значит маршрутизируется в туннель и попадает в наш стек.
// Адрес самого интерфейса для этого не годится: его ядро считает своим и обрабатывает
// пакеты само.
func (p *Pool) ServiceAddr() netip.Addr { return p.service }

// Assign выдаёт имени адрес, повторно отдавая тот же при следующих запросах.
func (p *Pool) Assign(name string) (netip.Addr, error) {
	name = normalize(name)
	if name == "" {
		return netip.Addr{}, fmt.Errorf("fakeip: пустое имя")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.nowFunc()
	if e, ok := p.byName[name]; ok {
		e.seen = now
		p.order.MoveToBack(e.el)
		return e.addr, nil
	}

	addr, err := p.allocate(now)
	if err != nil {
		return netip.Addr{}, err
	}

	e := &entry{name: name, addr: addr, seen: now}
	e.el = p.order.PushBack(e)
	p.byName[name] = e
	p.byAddr[addr] = e
	return addr, nil
}

// allocate находит свободный адрес.
func (p *Pool) allocate(now time.Time) (netip.Addr, error) {
	// Сперва раздаём ещё не тронутые адреса: пока диапазон не кончился, переиспользовать
	// нечего, и вытеснять никого не надо.
	if p.next.Compare(p.last) <= 0 {
		addr := p.next
		p.next = p.next.Next()
		return addr, nil
	}

	// Диапазон исчерпан — вытесняем самую старую аренду, но только если она уже пережила
	// свой срок. Отбирать адрес у имени, которым только что пользовались, значит увести
	// живое соединение на чужой сайт.
	front := p.order.Front()
	if front == nil {
		return netip.Addr{}, fmt.Errorf("fakeip: диапазон %s исчерпан", p.prefix)
	}
	oldest := front.Value.(*entry)
	if now.Sub(oldest.seen) < p.lease {
		return netip.Addr{}, fmt.Errorf(
			"fakeip: диапазон %s исчерпан, самой старой аренде всего %s", p.prefix, now.Sub(oldest.seen).Round(time.Second))
	}

	p.order.Remove(front)
	delete(p.byName, oldest.name)
	delete(p.byAddr, oldest.addr)
	return oldest.addr, nil
}

// Lookup возвращает имя, которому выдан адрес.
func (p *Pool) Lookup(addr netip.Addr) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	e, ok := p.byAddr[addr.Unmap()]
	if !ok {
		return "", false
	}
	e.seen = p.nowFunc()
	p.order.MoveToBack(e.el)
	return e.name, true
}

// SetReal запоминает настоящие адреса имени.
//
// Кладутся рядом с подменным, а не отдельным кешем: живут они ровно столько же, сколько
// подменный адрес, и вычищаться должны вместе с ним.
func (p *Pool) SetReal(name string, addrs []netip.Addr) {
	name = normalize(name)
	if name == "" || len(addrs) == 0 {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.byName[name]; ok {
		e.real = addrs
	}
}

// Real отдаёт настоящие адреса по подменному. Пусто означает, что их не узнавали.
func (p *Pool) Real(addr netip.Addr) []netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()

	e, ok := p.byAddr[addr.Unmap()]
	if !ok {
		return nil
	}
	return e.real
}

// Contains сообщает, из нашего ли диапазона адрес.
func (p *Pool) Contains(addr netip.Addr) bool {
	return addr.Is4() && p.prefix.Contains(addr.Unmap())
}

// Len возвращает число выданных адресов.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byName)
}

// normalize приводит имя к виду, в котором оно сравнивается.
func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// lastAddr возвращает последний адрес диапазона.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	bits := p.Bits()
	for i := bits; i < 32; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	return netip.AddrFrom4(b)
}
