package dnscache

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNS — настоящий сервер DNS на петле: пакеты собираются и разбираются по-честному,
// иначе проверялся бы не резолвер, а заглушка.
type fakeDNS struct {
	addr    string
	queries atomic.Int64
	// answer решает, что отвечать. Пустой список означает отказ.
	answer func(name string, qtype dnsmessage.Type) ([]dnsmessage.Resource, dnsmessage.RCode)
	dead   atomic.Bool
}

func newFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("сокет: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	f := &fakeDNS{addr: pc.LocalAddr().String()}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if f.dead.Load() {
				continue
			}
			f.queries.Add(1)

			var msg dnsmessage.Message
			if err := msg.Unpack(buf[:n]); err != nil || len(msg.Questions) == 0 {
				continue
			}
			q := msg.Questions[0]

			answers, rcode := f.answer(strings.TrimSuffix(q.Name.String(), "."), q.Type)
			reply := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:            msg.Header.ID,
					Response:      true,
					Authoritative: true,
					RCode:         rcode,
				},
				Questions: msg.Questions,
				Answers:   answers,
			}
			packed, err := reply.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(packed, from)
		}
	}()
	return f
}

func aRecord(name string, ip [4]byte, ttl uint32) dnsmessage.Resource {
	n, _ := dnsmessage.NewName(name + ".")
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl,
		},
		Body: &dnsmessage.AResource{A: ip},
	}
}

func answerA(name string, ip [4]byte, ttl uint32) func(string, dnsmessage.Type) ([]dnsmessage.Resource, dnsmessage.RCode) {
	return func(q string, qtype dnsmessage.Type) ([]dnsmessage.Resource, dnsmessage.RCode) {
		if qtype != dnsmessage.TypeA || q != name {
			return nil, dnsmessage.RCodeSuccess
		}
		return []dnsmessage.Resource{aRecord(name, ip, ttl)}, dnsmessage.RCodeSuccess
	}
}

func TestResolverAsksAndCaches(t *testing.T) {
	srv := newFakeDNS(t)
	srv.answer = answerA("example.com", [4]byte{93, 184, 215, 14}, 300)

	r := New(Config{
		Primary: srv.addr,
		Cache:   Options{MaxEntries: 100},
		Log:     slog.New(slog.DiscardHandler),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := r.Resolve(ctx, "example.com", "ip4")
	if err != nil {
		t.Fatalf("разрешение: %v", err)
	}
	if len(got) != 1 || got[0].String() != "93.184.215.14" {
		t.Fatalf("адреса не те: %v", got)
	}
	if n := srv.queries.Load(); n != 1 {
		t.Fatalf("запросов к серверу: %d", n)
	}

	// Второй раз — из кеша, сервер тревожить не за чем.
	if _, err := r.Resolve(ctx, "example.com", "ip4"); err != nil {
		t.Fatalf("повторное разрешение: %v", err)
	}
	if n := srv.queries.Load(); n != 1 {
		t.Fatalf("кеш не сработал: запросов %d", n)
	}
	if s := r.Stats(); s.Hits != 1 || s.Entries != 1 {
		t.Fatalf("статистика кеша: %+v", s)
	}
}

// Молчащий первичный — вопрос уходит вторичному. Ради этого их и два.
func TestResolverFallsBackToSecondary(t *testing.T) {
	primary := newFakeDNS(t)
	primary.answer = answerA("example.com", [4]byte{1, 1, 1, 1}, 300)
	primary.dead.Store(true) // молчит

	secondary := newFakeDNS(t)
	secondary.answer = answerA("example.com", [4]byte{9, 9, 9, 9}, 300)

	r := New(Config{
		Primary:   primary.addr,
		Secondary: secondary.addr,
		Cache:     Options{MaxEntries: 100},
		Log:       slog.New(slog.DiscardHandler),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	got, err := r.Resolve(ctx, "example.com", "ip4")
	if err != nil {
		t.Fatalf("разрешение: %v", err)
	}
	if len(got) != 1 || got[0].String() != "9.9.9.9" {
		t.Fatalf("ответ пришёл не от вторичного: %v", got)
	}
}

// Сброс кеша заставляет спросить заново.
func TestResolverFlushForcesFreshQuery(t *testing.T) {
	srv := newFakeDNS(t)
	srv.answer = answerA("example.com", [4]byte{93, 184, 215, 14}, 3600)

	r := New(Config{Primary: srv.addr, Cache: Options{MaxEntries: 100}})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := r.Resolve(ctx, "example.com", "ip4"); err != nil {
		t.Fatalf("разрешение: %v", err)
	}
	if n := r.Flush(); n != 1 {
		t.Fatalf("сброшено записей: %d", n)
	}
	if _, err := r.Resolve(ctx, "example.com", "ip4"); err != nil {
		t.Fatalf("разрешение после сброса: %v", err)
	}
	if n := srv.queries.Load(); n != 2 {
		t.Fatalf("после сброса сервер спросили %d раз вместо 2", n)
	}
}

// Смена адресов действует на ходу, кеш при этом не трогается: адреса имён от того, кто их
// назвал, не зависят.
func TestResolverReconfigures(t *testing.T) {
	first := newFakeDNS(t)
	first.answer = answerA("a.example", [4]byte{1, 1, 1, 1}, 300)
	second := newFakeDNS(t)
	second.answer = answerA("b.example", [4]byte{2, 2, 2, 2}, 300)

	r := New(Config{Primary: first.addr, Cache: Options{MaxEntries: 100}})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := r.Resolve(ctx, "a.example", "ip4"); err != nil {
		t.Fatalf("разрешение: %v", err)
	}

	r.Configure(Config{Primary: second.addr, Cache: Options{MaxEntries: 100}})

	if _, err := r.Resolve(ctx, "b.example", "ip4"); err != nil {
		t.Fatalf("после смены резолвера: %v", err)
	}
	// Прежний ответ остался в кеше.
	if s := r.Stats(); s.Entries != 2 {
		t.Fatalf("в кеше %d записей, смена резолвера его почистила", s.Entries)
	}
}

// Литерал адреса разрешать некуда и незачем.
func TestResolverPassesLiteralsThrough(t *testing.T) {
	srv := newFakeDNS(t)
	srv.answer = answerA("nothing", [4]byte{1, 1, 1, 1}, 300)

	r := New(Config{Primary: srv.addr, Cache: Options{MaxEntries: 10}})
	got, err := r.Resolve(context.Background(), "192.0.2.7", "ip4")
	if err != nil {
		t.Fatalf("литерал: %v", err)
	}
	if len(got) != 1 || got[0].String() != "192.0.2.7" {
		t.Fatalf("литерал испортился: %v", got)
	}
	if n := srv.queries.Load(); n != 0 {
		t.Fatalf("литерал ушёл на резолвер: %d запросов", n)
	}
}

func TestResolverWithoutServers(t *testing.T) {
	r := New(Config{Cache: Options{MaxEntries: 10}})
	_, err := r.Resolve(context.Background(), "example.com", "ip4")
	if !errors.Is(err, ErrNoResolvers) {
		t.Fatalf("ждали ErrNoResolvers, получили %v", err)
	}
}

// Время жизни берётся из ответа сервера, а не выдумывается.
func TestResolverHonoursServerTTL(t *testing.T) {
	srv := newFakeDNS(t)
	srv.answer = answerA("example.com", [4]byte{93, 184, 215, 14}, 1)

	c := newClock()
	r := New(Config{Primary: srv.addr, Cache: Options{MaxEntries: 10, Now: c.Now}})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := r.Resolve(ctx, "example.com", "ip4"); err != nil {
		t.Fatalf("разрешение: %v", err)
	}
	c.Advance(2 * time.Second)
	if _, err := r.Resolve(ctx, "example.com", "ip4"); err != nil {
		t.Fatalf("повтор: %v", err)
	}
	if n := srv.queries.Load(); n != 2 {
		t.Fatalf("TTL в одну секунду не сработал: запросов %d", n)
	}
}
