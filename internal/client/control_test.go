package client

import (
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/jaywehosl/quic-diver/internal/routing"
)

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// Галку двигают при работающем клиенте, и работать она обязана сразу: требовать
// переподключения ради умолчания маршрутизации означало бы рвать все живые соединения.
func TestSetViaExitChangesDefaultOnTheFly(t *testing.T) {
	engine, err := routing.New(nil, routing.ActionDirect, quiet())
	if err != nil {
		t.Fatalf("движок: %v", err)
	}

	c := NewControl()
	c.attach(engine, quiet())

	if !c.SetViaExit(true) {
		t.Fatal("переключатель отказал при живом движке")
	}
	if got := engine.Decide(routing.Flow{Domain: "example.com"}).Action; got != routing.ActionEgress {
		t.Fatalf("после включения умолчание %q", got)
	}

	if !c.SetViaExit(false) {
		t.Fatal("переключатель отказал на обратном ходу")
	}
	if got := engine.Decide(routing.Flow{Domain: "example.com"}).Action; got != routing.ActionDirect {
		t.Fatalf("после выключения умолчание %q", got)
	}
}

// Правило сильнее галки и всегда было сильнее: поток, который правило шлёт на выход, пойдёт
// на выход и при снятой галке. Иначе правила означали бы не то, что в них написано.
func TestRulesOutrankTheCheckbox(t *testing.T) {
	rules := []routing.Rule{{Match: []string{"domain:example.com"}, Action: string(routing.ActionEgress)}}
	engine, err := routing.New(rules, routing.ActionDirect, quiet())
	if err != nil {
		t.Fatalf("движок: %v", err)
	}

	c := NewControl()
	c.attach(engine, quiet())
	c.SetViaExit(false)

	if got := engine.Decide(routing.Flow{Domain: "example.com"}).Action; got != routing.ActionEgress {
		t.Fatalf("правило проиграло галке: %q", got)
	}
	if got := engine.Decide(routing.Flow{Domain: "other.com"}).Action; got != routing.ActionDirect {
		t.Fatalf("умолчание не сработало для остальных: %q", got)
	}
}

// closeSpy — поток, который умеет сказать, что его закрыли.
type closeSpy struct{ closed atomic.Bool }

func (c *closeSpy) Close() error {
	c.closed.Store(true)
	return nil
}

// Переключение закрывает открытые потоки.
//
// Без этого браузер продолжает переиспользовать прежние соединения, и человек видит старый
// маршрут: одна вкладка показывает одно, другая другое. Половинчатая картина хуже обрыва.
func TestSwitchingClosesLiveStreams(t *testing.T) {
	engine, err := routing.New(nil, routing.ActionDirect, quiet())
	if err != nil {
		t.Fatalf("движок: %v", err)
	}

	c := NewControl()
	c.attach(engine, quiet())

	local, remote := &closeSpy{}, &closeSpy{}
	id := c.track(pair{local: local, remote: remote})
	if c.live() != 1 {
		t.Fatalf("поток не встал на учёт: живых %d", c.live())
	}

	if !c.SetViaExit(true) {
		t.Fatal("переключатель отказал")
	}
	if !local.closed.Load() || !remote.closed.Load() {
		t.Fatalf("половины потока остались открыты: local=%v remote=%v",
			local.closed.Load(), remote.closed.Load())
	}
	if c.live() != 0 {
		t.Fatalf("после переключения на учёте осталось %d", c.live())
	}

	// Снятие с учёта закончившегося потока не должно ничего ломать: он уже закрыт.
	c.untrack(id)
}

// Повторное нажатие ничего не меняет — и рвать ничего не должно. Иначе человек, дважды
// коснувшийся галки, терял бы работающие соединения на ровном месте.
func TestSameValueKeepsStreams(t *testing.T) {
	engine, err := routing.New(nil, routing.ActionEgress, quiet())
	if err != nil {
		t.Fatalf("движок: %v", err)
	}

	c := NewControl()
	c.attach(engine, quiet())

	spy := &closeSpy{}
	c.track(pair{local: spy, remote: &closeSpy{}})

	if !c.SetViaExit(true) {
		t.Fatal("переключатель отказал на том же значении")
	}
	if spy.closed.Load() {
		t.Fatal("поток закрыт, хотя умолчание не менялось")
	}
	if c.live() != 1 {
		t.Fatalf("поток пропал с учёта: живых %d", c.live())
	}
}

// Поток, закончившийся сам, снимается с учёта и на переключении уже не всплывает.
func TestFinishedStreamLeavesRegistry(t *testing.T) {
	engine, _ := routing.New(nil, routing.ActionDirect, quiet())
	c := NewControl()
	c.attach(engine, quiet())

	spy := &closeSpy{}
	id := c.track(pair{local: spy, remote: &closeSpy{}})
	c.untrack(id)

	c.SetViaExit(true)
	if spy.closed.Load() {
		t.Fatal("закрыт поток, снятый с учёта")
	}
}

// Клиент не запущен — двигать нечего, и переключатель обязан сказать об этом, а не молча
// сделать вид, что сработал: приложение по этому ответу решает, показывать ли отклик.
func TestSetViaExitWithoutRunningClient(t *testing.T) {
	if NewControl().SetViaExit(true) {
		t.Fatal("переключатель отчитался об успехе без работающего клиента")
	}

	var nothing *Control
	if nothing.SetViaExit(true) {
		t.Fatal("пустой переключатель отчитался об успехе")
	}
}

// Клиент остановился — рычаг обязан отвязаться, иначе он двигал бы движок мёртвого клиента.
func TestControlDetaches(t *testing.T) {
	engine, err := routing.New(nil, routing.ActionDirect, quiet())
	if err != nil {
		t.Fatalf("движок: %v", err)
	}

	c := NewControl()
	c.attach(engine, quiet())
	c.detach()

	if c.SetViaExit(true) {
		t.Fatal("переключатель сработал после остановки клиента")
	}
}
