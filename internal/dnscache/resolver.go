package dnscache

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Резолвер узла.
//
// Свой, а не системный, по трём причинам, и все три из ТЗ: первичный и вторичный адреса
// задаются администратором, время жизни ответа переопределяется, кеш сбрасывается без
// перезапуска. Системный резолвер не умеет ничего из этого.
//
// Разбор пакетов взят у golang.org/x/net/dns/dnsmessage — той же библиотеки, которой
// пользуется сама stdlib. Свой разбор DNS писать незачем: это не то место, где нужны
// особенности.

const (
	// queryTimeout — сколько ждём один сервер.
	queryTimeout = 5 * time.Second
	// maxUDPResponse — потолок ответа по UDP. Больше — переспрашиваем по TCP.
	maxUDPResponse = 4096
	// defaultTTL — что берём, если сервер не сказал ничего внятного.
	defaultTTL = 5 * time.Minute
)

// ErrNoResolvers означает, что спрашивать некого.
var ErrNoResolvers = errors.New("dnscache: не задан ни один резолвер")

// Config — настройки резолвера.
type Config struct {
	// Primary и Secondary — адреса вида "1.1.1.1:53". Вторичный спрашивается, только если
	// первичный не ответил или ответил ошибкой.
	Primary, Secondary string
	// Cache — настройки кеша.
	Cache Options
	// Log — куда писать.
	Log *slog.Logger
}

// Resolver разрешает имена для узла.
type Resolver struct {
	mu                  sync.RWMutex
	primary, secondary  string
	cache               *Cache
	log                 *slog.Logger
	dial                func(ctx context.Context, network, addr string) (net.Conn, error)
	failoverToSecondary uint64
}

// New собирает резолвер.
func New(cfg Config) *Resolver {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	d := &net.Dialer{Timeout: queryTimeout}
	return &Resolver{
		primary:   cfg.Primary,
		secondary: cfg.Secondary,
		cache:     NewCache(cfg.Cache),
		log:       cfg.Log,
		dial:      d.DialContext,
	}
}

// Configure меняет адреса и настройки кеша на ходу.
//
// Смена резолвера кеш не чистит: адреса имён от того, кто их назвал, не зависят. Чистка —
// отдельное действие, у неё своя причина (Flush).
func (r *Resolver) Configure(cfg Config) {
	r.mu.Lock()
	r.primary, r.secondary = cfg.Primary, cfg.Secondary
	r.mu.Unlock()

	r.cache.Configure(cfg.Cache)
}

// Flush опустошает кеш и говорит, сколько записей выбросил.
func (r *Resolver) Flush() int { return r.cache.Flush() }

// Stats — состояние кеша.
func (r *Resolver) Stats() Stats { return r.cache.Stats() }

// Resolve разрешает имя. network — "ip4", "ip6" или "ip" для обоих семейств.
func (r *Resolver) Resolve(ctx context.Context, name, network string) ([]netip.Addr, error) {
	// Литерал разрешать не нужно и вредно: запрос ушёл бы в никуда, а ответ и так известен.
	if addr, err := netip.ParseAddr(name); err == nil {
		return []netip.Addr{addr}, nil
	}

	switch network {
	case "ip4", "ip6":
		return r.resolveOne(ctx, name, network)
	case "ip", "":
		return r.resolveBoth(ctx, name)
	default:
		return nil, fmt.Errorf("dnscache: неизвестное семейство %q", network)
	}
}

// resolveBoth спрашивает оба семейства сразу.
//
// Сразу, а не по очереди: последовательный опрос стоил бы двух задержек подряд, а имя,
// живущее только в v6, ждало бы впустую отказа по v4.
func (r *Resolver) resolveBoth(ctx context.Context, name string) ([]netip.Addr, error) {
	type result struct {
		addrs []netip.Addr
		err   error
	}
	v4c := make(chan result, 1)
	go func() {
		addrs, err := r.resolveOne(ctx, name, "ip4")
		v4c <- result{addrs, err}
	}()
	v6, err6 := r.resolveOne(ctx, name, "ip6")
	v4 := <-v4c

	addrs := append(v4.addrs, v6...)
	if len(addrs) > 0 {
		return addrs, nil
	}
	if v4.err != nil {
		return nil, v4.err
	}
	if err6 != nil {
		return nil, err6
	}
	return nil, fmt.Errorf("dnscache: у имени %s нет адресов", name)
}

func (r *Resolver) resolveOne(ctx context.Context, name, network string) ([]netip.Addr, error) {
	if addrs, ok := r.cache.Get(name, network); ok {
		return addrs, nil
	}

	r.mu.RLock()
	primary, secondary := r.primary, r.secondary
	r.mu.RUnlock()

	if primary == "" && secondary == "" {
		return nil, ErrNoResolvers
	}

	var errs []error
	for i, server := range []string{primary, secondary} {
		if server == "" {
			continue
		}
		started := time.Now()
		addrs, ttl, err := r.ask(ctx, server, name, network)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", server, err))
			if i == 0 {
				r.log.Debug("первичный резолвер не ответил, спрашиваю вторичный",
					"server", server, "name", name, "err", err)
			}
			continue
		}
		stored := r.cache.Put(name, network, addrs, ttl)
		// Промах кеша виден в журнале, попадание — нет. Так по журналу узла понятно, что
		// кеш работает: имя, спрошенное дважды, появляется здесь один раз.
		//
		// Время жизни печатается дважды, когда зажим его изменил: разница между тем, что
		// сказал сервер, и тем, что лежит в кеше, — это и есть работа настройки.
		fields := []any{
			"name", name, "family", network, "server", server,
			"адресов", len(addrs), "ttl_с", int(ttl.Seconds()),
			"мс", time.Since(started).Milliseconds(),
		}
		if stored != ttl && stored > 0 {
			fields = append(fields, "ttl_в_кеше_с", int(stored.Seconds()))
		}
		r.log.Debug("имя разрешено запросом", fields...)
		return addrs, nil
	}
	return nil, fmt.Errorf("dnscache: имя %s не разрешилось: %w", name, errors.Join(errs...))
}

// ask спрашивает один сервер: сперва по UDP, при усечении — по TCP.
func (r *Resolver) ask(ctx context.Context, server, name, network string) ([]netip.Addr, time.Duration, error) {
	qtype := dnsmessage.TypeA
	if network == "ip6" {
		qtype = dnsmessage.TypeAAAA
	}

	fqdn, err := dnsmessage.NewName(dnsName(name))
	if err != nil {
		return nil, 0, fmt.Errorf("негодное имя: %w", err)
	}

	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: fqdn, Type: qtype, Class: dnsmessage.ClassINET}},
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	raw, truncated, err := r.exchangeUDP(ctx, server, msg)
	if err != nil {
		return nil, 0, err
	}
	if truncated {
		// Усечённый ответ переспрашивается по TCP — так велит RFC 1035 §4.2.1, и без этого
		// имена с длинными списками адресов разрешались бы наполовину.
		if raw, err = r.exchangeTCP(ctx, server, msg); err != nil {
			return nil, 0, err
		}
	}
	return parseAnswer(raw, qtype)
}

func (r *Resolver) exchangeUDP(ctx context.Context, server string, msg dnsmessage.Message) ([]byte, bool, error) {
	packed, err := msg.Pack()
	if err != nil {
		return nil, false, err
	}

	conn, err := r.dial(ctx, "udp", server)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(packed); err != nil {
		return nil, false, err
	}

	buf := make([]byte, maxUDPResponse)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}

	var header dnsmessage.Parser
	h, err := header.Start(buf[:n])
	if err != nil {
		return nil, false, fmt.Errorf("ответ не разбирается: %w", err)
	}
	if h.ID != msg.Header.ID {
		return nil, false, errors.New("ответ не на наш запрос")
	}
	return buf[:n], h.Truncated, nil
}

func (r *Resolver) exchangeTCP(ctx context.Context, server string, msg dnsmessage.Message) ([]byte, error) {
	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	conn, err := r.dial(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// По TCP сообщению предшествует его длина (RFC 7766 §8).
	framed := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(framed, uint16(len(packed)))
	copy(framed[2:], packed)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}

	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(length[:])
	if size == 0 {
		return nil, errors.New("пустой ответ по TCP")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

// parseAnswer достаёт адреса и наименьшее время жизни из ответа.
//
// Наименьшее, потому что запись живёт целиком: держать в кеше часть адресов дольше прочих
// значило бы отдавать неполный ответ и не знать об этом.
func parseAnswer(raw []byte, want dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	var p dnsmessage.Parser
	h, err := p.Start(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("ответ не разбирается: %w", err)
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return nil, 0, fmt.Errorf("резолвер ответил %s", h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, 0, err
	}

	var (
		addrs []netip.Addr
		ttl   = time.Duration(0)
	)
	for {
		hdr, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, 0, err
		}

		var addr netip.Addr
		switch {
		case hdr.Type == dnsmessage.TypeA && want == dnsmessage.TypeA:
			res, err := p.AResource()
			if err != nil {
				return nil, 0, err
			}
			addr = netip.AddrFrom4(res.A)
		case hdr.Type == dnsmessage.TypeAAAA && want == dnsmessage.TypeAAAA:
			res, err := p.AAAAResource()
			if err != nil {
				return nil, 0, err
			}
			addr = netip.AddrFrom16(res.AAAA)
		default:
			// Промежуточные CNAME и всё прочее пропускаем: нас интересуют адреса.
			if err := p.SkipAnswer(); err != nil {
				return nil, 0, err
			}
			continue
		}

		addrs = append(addrs, addr)
		if got := time.Duration(hdr.TTL) * time.Second; ttl == 0 || got < ttl {
			ttl = got
		}
	}

	if len(addrs) == 0 {
		return nil, 0, fmt.Errorf("в ответе нет адресов")
	}
	if ttl == 0 {
		ttl = defaultTTL
	}
	return addrs, ttl, nil
}

// dnsName приводит имя к виду с точкой на конце.
func dnsName(name string) string {
	if len(name) > 0 && name[len(name)-1] == '.' {
		return name
	}
	return name + "."
}
