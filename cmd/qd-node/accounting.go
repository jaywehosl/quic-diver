package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jaywehosl/quic-diver/internal/config"
	"github.com/jaywehosl/quic-diver/internal/control"
	"github.com/jaywehosl/quic-diver/internal/ledger"
	"github.com/jaywehosl/quic-diver/internal/store"
)

// Учёт трафика и лимиты (решение 001 §2).
//
// Считает тот узел, который открыл сокет наружу. Клиент, работающий через выход, попадает в
// счёт выходного узла — своего имени тот не знает, оно приезжает с потоком.
//
// Лимиты мягкие. Между обменами клиент может перебрать, и переберёт, — взамен соблюдается
// правило поважнее: недоступность соседей никогда не отказ клиенту.

// sweepPeriod — как часто выметаются истёкшие сессии.
const sweepPeriod = 30 * time.Second

// accounting связывает динамическую базу с журналом: лимиты живут в журнале, расход — в
// памяти, а решение принимается по обоим сразу.
type accounting struct {
	ledger *ledger.Ledger
	store  *store.Store
	log    *slog.Logger
}

func newAccounting(l *ledger.Ledger, st *store.Store, log *slog.Logger) *accounting {
	return &accounting{ledger: l, store: st, log: log}
}

// Count записывает расход клиента. Реализует node.Meter.
func (a *accounting) Count(client string, sent, received uint64) {
	a.ledger.Add(client, a.periodOf(client), sent, received)
}

// periodOf — расчётный период клиента. Пустой означает, что счётчик не обнуляется.
func (a *accounting) periodOf(client string) string {
	c, ok := a.store.State().Client(client)
	if !ok {
		return ""
	}
	return ledger.PeriodOf(c.Limits.TrafficPeriod, time.Now())
}

// Admit решает, пускать ли клиента. Реализует node.Sessions.
func (a *accounting) Admit(client, device, addr string) (bool, string) {
	c, ok := a.store.State().Client(client)
	if !ok {
		// Клиента нет в журнале — но сюда он попал только после сошедшегося приветствия,
		// значит журнал у нас отстал. Отказывать в этом случае нельзя: свежий клиент,
		// заведённый минуту назад, не должен ждать, пока запись обойдёт сеть.
		a.log.Warn("клиент опознан, но его нет в журнале — пускаю", "id", client)
		return true, ""
	}
	v := a.ledger.Check(c, device, addr, time.Now())
	return v.Allowed, v.Reason
}

// Active отмечает работающее устройство. Реализует node.Sessions.
func (a *accounting) Active(client, device, addr, conn string) {
	a.ledger.SessionUp(client, device, addr, conn)
}

// Gone отмечает уход. Реализует node.Sessions.
func (a *accounting) Gone(client, conn string) {
	a.ledger.SessionDown(client, conn)
}

// usageOf собирает расход клиента для снапшота.
//
// Человек должен видеть, сколько потратил и сколько осталось, а не узнавать об исчерпании
// лимита по внезапному отказу.
func (a *accounting) usageOf(client string) *control.Usage {
	c, ok := a.store.State().Client(client)
	if !ok {
		return nil
	}

	period := ledger.PeriodOf(c.Limits.TrafficPeriod, time.Now())
	spent := a.ledger.Total(client, period)
	return &control.Usage{
		Sent:        spent.Sent,
		Received:    spent.Received,
		LimitBytes:  c.Limits.TrafficBytes,
		Period:      c.Limits.TrafficPeriod,
		Devices:     a.ledger.Devices(client),
		DeviceLimit: c.Limits.Devices,
	}
}

// sweep выметает истёкшие сессии и сохраняет расход, пока жив контекст.
func (a *accounting) sweep(ctx context.Context) {
	ticker := time.NewTicker(sweepPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Последний слепок перед уходом: узел, остановленный командой, не должен
			// терять посчитанное за время после прошлого сохранения.
			a.save()
			return
		case <-ticker.C:
			if n := a.ledger.Sweep(); n > 0 {
				a.log.Debug("выметены истёкшие сессии", "count", n)
			}
			a.save()
		}
	}
}

// printUsage печатает расход, посчитанный этим узлом.
//
// Администратор работает офлайн, журналом через файлы, и цифр расхода у него нет неоткуда:
// расход — динамика, он не подписан и по журналу не ходит. Пока нет панели, посмотреть его
// можно там же, где он и считается, — на самом узле.
func printUsage(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	fingerprint, err := cfg.Fingerprint()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.StorePath(), fingerprint)
	if err != nil {
		return err
	}
	defer st.Close()

	cells, err := st.LoadUsage()
	if err != nil {
		return err
	}
	if len(cells) == 0 {
		fmt.Printf("узел %s ничего пока не насчитал\n", cfg.ID)
		return nil
	}

	fmt.Printf("расход, посчитанный узлом %s:\n", cfg.ID)
	fmt.Println("(только своя доля — итог по сети складывается из долей всех узлов)")
	state := st.State()
	for _, c := range cells {
		period := c.Period
		if period == "" {
			period = "за всё время"
		}
		limit := ""
		if client, ok := state.Client(c.Client); ok && client.Limits.TrafficBytes > 0 {
			limit = fmt.Sprintf(", лимит %d ГБ", client.Limits.TrafficBytes>>30)
		}
		total := c.Sent + c.Received
		fmt.Printf("  %-12s %-14s %8.2f ГБ (наружу %.2f, обратно %.2f)%s\n",
			c.Client, period, gib(total), gib(c.Sent), gib(c.Received), limit)
	}
	return nil
}

func gib(b uint64) float64 { return float64(b) / (1 << 30) }

// restore поднимает расход с диска.
//
// Без этого лимит «пятьдесят гигабайт в месяц» не работал бы вовсе: счётчик обнулялся бы на
// каждом обновлении узла, и потолок превращался бы в пожелание.
func (a *accounting) restore() {
	cells, err := a.store.LoadUsage()
	if err != nil {
		a.log.Error("расход с диска не прочитан, считаем заново", "err", err)
		return
	}
	if len(cells) == 0 {
		return
	}

	own := make([]ledger.Cell, 0, len(cells))
	var total uint64
	for _, c := range cells {
		own = append(own, ledger.Cell{
			Client: c.Client,
			Period: c.Period,
			Usage:  ledger.Usage{Sent: c.Sent, Received: c.Received},
		})
		total += c.Sent + c.Received
	}
	a.ledger.Restore(own)
	a.log.Info("расход поднят с диска", "ячеек", len(own), "всего_мб", total>>20)
}

// save кладёт наши ячейки на диск.
func (a *accounting) save() {
	own := a.ledger.Own()
	if len(own) == 0 {
		return
	}

	cells := make([]store.UsageCell, 0, len(own))
	for _, c := range own {
		cells = append(cells, store.UsageCell{
			Client:   c.Client,
			Period:   c.Period,
			Sent:     c.Usage.Sent,
			Received: c.Usage.Received,
		})
	}
	if err := a.store.SaveUsage(cells); err != nil {
		a.log.Error("расход не сохранён", "err", err)
	}
}
