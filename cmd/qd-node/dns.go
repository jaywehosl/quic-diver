package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/jaywehosl/quic-diver/internal/dnscache"
	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/store"
)

// Резолвер узла и его настройки из журнала.
//
// Всё, что просит ТЗ, — первичный и вторичный адреса, потолок записей, переопределение
// времени жизни, мягкий сброс — задаётся администратором записью в журнале и применяется
// без перезапуска: узел следит за журналом и перенастраивает резолвер на месте.

// defaultResolvers — куда ходить, пока администратор не сказал иначе.
//
// Два разных оператора намеренно: смысл вторичного адреса в том, чтобы пережить беду
// первого, а две машины одного хозяина падают вместе.
const (
	defaultPrimary   = "1.1.1.1:53"
	defaultSecondary = "9.9.9.9:53"
)

// newResolver собирает резолвер по текущему состоянию журнала.
func newResolver(st *store.Store, log *slog.Logger) *dnscache.Resolver {
	r := dnscache.New(resolverConfig(st.State().Settings(), log))
	return r
}

// resolverConfig переводит настройки сети в настройки резолвера.
func resolverConfig(s oplog.Settings, log *slog.Logger) dnscache.Config {
	primary, secondary := s.DNSPrimary, s.DNSSecondary
	if primary == "" {
		primary, secondary = defaultPrimary, defaultSecondary
	}
	return dnscache.Config{
		Primary:   primary,
		Secondary: secondary,
		Cache: dnscache.Options{
			MaxEntries: s.DNSCacheEntries,
			MinTTL:     time.Duration(s.DNSMinTTL) * time.Second,
			MaxTTL:     time.Duration(s.DNSMaxTTL) * time.Second,
		},
		Log: log,
	}
}

// watchDNS перенастраивает резолвер, пока жив контекст.
//
// Читает журнал, а не конфиг: параметры сети общие для всех узлов, и менять их по одному
// руками — верный способ получить сеть, где половина узлов живёт по старым правилам.
func watchDNS(ctx context.Context, st *store.Store, r *dnscache.Resolver, log *slog.Logger) {
	applied := st.State().Settings()
	describe(applied, r, log)

	for {
		changed := st.Changed()
		select {
		case <-changed:
		case <-ctx.Done():
			return
		}

		now := st.State().Settings()
		if now == applied {
			// Журнал изменился, но не в этой части: чаще всего добавили клиента.
			continue
		}

		r.Configure(resolverConfig(now, log))
		// Сброс — по метке: узел, поднявшийся позже команды, увидит её здесь же и
		// выполнит, хотя в момент команды его не было в живых.
		if now.DNSFlushAt > applied.DNSFlushAt {
			log.Info("мягкий сброс кеша имён", "выброшено", r.Flush())
		}
		applied = now
		describe(applied, r, log)
	}
}

func describe(s oplog.Settings, r *dnscache.Resolver, log *slog.Logger) {
	cfg := resolverConfig(s, nil)
	stats := r.Stats()
	log.Info("резолвер узла",
		"первичный", cfg.Primary, "вторичный", orNone(cfg.Secondary),
		"кеш_записей", stats.MaxEntries,
		"ttl_от", s.DNSMinTTL, "ttl_до", s.DNSMaxTTL)
}

func orNone(s string) string {
	if s == "" {
		return "нет"
	}
	return s
}
