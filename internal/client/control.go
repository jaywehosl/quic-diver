package client

import (
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/jaywehosl/quic-diver/internal/link"
	"github.com/jaywehosl/quic-diver/internal/routing"
)

// Control — рычаги, которые человек двигает при работающем клиенте.
//
// Отдельно от Options намеренно: Options — это то, с чем клиент запускается, и меняться на
// ходу оно не может. А «через выходные узлы» человек переключает часто, и требовать ради
// этого переподключения означало бы рвать все живые соединения ради одной галки.
//
// Пустой Control работать не мешает: рычаг, к которому ничего не подключено, молча ничего не
// делает — клиент мог быть запущен и без него.
type Control struct {
	engine atomic.Pointer[routing.Engine]
	log    atomic.Pointer[slog.Logger]
	// streams — живые потоки. Переключение закрывает их, иначе картина получается
	// половинчатой: браузер переиспользует открытые соединения, и часть трафика остаётся на
	// прежнем маршруте, пока он их не отпустит.
	streams *streams
	// link — живая связь с узлом. Нужна, чтобы менять потолок скорости, не переподключаясь:
	// сама скорость держится на одном числе внутри контроллера (см. internal/node/rate.go).
	link atomic.Pointer[link.Link]
}

// NewControl заводит рычаги.
func NewControl() *Control { return &Control{streams: newStreams()} }

// attach связывает рычаги с работающим движком правил.
func (c *Control) attach(e *routing.Engine, log *slog.Logger) {
	if c != nil {
		c.engine.Store(e)
		c.log.Store(log)
	}
}

// attachLink связывает рычаги с живой связью.
func (c *Control) attachLink(l *link.Link) {
	if c != nil {
		c.link.Store(l)
	}
}

// detach отвязывает рычаги: клиент остановлен, двигать нечего.
func (c *Control) detach() {
	if c != nil {
		c.engine.Store(nil)
		c.link.Store(nil)
	}
}

// SetSendMbps меняет потолок отправки клиента на живом соединении.
//
// Без переподключения: скорость BRUTAL держится на одном числе внутри контроллера, и менять
// его можно на ходу. Рвать связь ради нового потолка означало бы обрывать человеку загрузку —
// как раз тогда, когда он подбирает число под свой канал и меняет его подряд несколько раз.
//
// Отвечает false, когда клиент не запущен или связи сейчас нет: тогда число просто запомнит
// приложение и применит при следующем запуске.
func (c *Control) SetSendMbps(mbps int) bool {
	if c == nil || mbps <= 0 {
		return false
	}
	l := c.link.Load()
	if l == nil {
		return false
	}
	conn := l.Current()
	if conn == nil {
		return false
	}
	conn.QUIC().SetBrutalSendMbps(mbps)
	if log := c.log.Load(); log != nil {
		log.Info("потолок отдачи изменён на лету", "отдача_мбит", mbps)
	}
	return true
}

// track берёт поток на учёт, если рычаги есть.
func (c *Control) track(p pair) uint64 {
	if c == nil {
		return 0
	}
	return c.streams.add(p)
}

// untrack снимает поток с учёта.
func (c *Control) untrack(id uint64) {
	if c != nil {
		c.streams.remove(id)
	}
}

// SetViaExit меняет умолчание маршрутизации на лету.
//
// Умолчание, а не приказ: правила сильнее его и всегда были сильнее. Поток, который правило
// шлёт на выход, пойдёт на выход и при снятой галке — иначе правила означали бы не то, что
// написано.
//
// Открытые потоки закрываются: перенести установленный сеанс на другой узел нельзя, а
// оставить его — значит показать человеку половину картины. Приложения переоткроют
// соединения сами, уже по новому маршруту.
//
// Возвращает false, когда двигать нечего: клиент не запущен.
func (c *Control) SetViaExit(on bool) bool {
	if c == nil {
		return false
	}
	e := c.engine.Load()
	if e == nil {
		return false
	}

	action := routing.ActionDirect
	if on {
		action = routing.ActionEgress
	}
	// Ничего не изменилось — и рвать нечего: повторное нажатие не должно обрывать работу.
	if e.Fallback() == action {
		return true
	}
	if err := e.SetFallback(action); err != nil {
		return false
	}

	closed := c.streams.closeAll()
	if log := c.log.Load(); log != nil {
		where := "наружу на входном узле"
		if on {
			where = "через выходные узлы"
		}
		// Про закрытые соединения говорим вслух: человек увидит, что вкладки перезагрузились,
		// и должен понимать, отчего это случилось.
		log.Info("маршрут по умолчанию сменён", "теперь", where, "закрыто_соединений", closed)
	}
	return true
}

// SetRules заменяет правила при работающем клиенте.
//
// Правила задаёт человек, и меняются они на ходу — как и галка. Открытые потоки при этом
// закрываются: правило, написанное только что, должно действовать на то, что человек видит
// перед собой, а не на то, что он откроет через полчаса.
//
// Возвращает ошибку, если правило негодное, и false-ошибку «клиент не запущен» отдельно —
// приложение по этому различает «не приняли» и «некуда применять».
func (c *Control) SetRules(rules []routing.Rule) error {
	if c == nil {
		return errNotRunning
	}
	e := c.engine.Load()
	if e == nil {
		return errNotRunning
	}
	if err := e.Replace(rules); err != nil {
		return err
	}

	closed := c.streams.closeAll()
	if log := c.log.Load(); log != nil {
		log.Info("правила заменены", "правил", len(rules), "закрыто_соединений", closed)
		for _, dead := range e.Inactive() {
			log.Warn("правило не работает без баз geosite/geoip", "rule", dead)
		}
	}
	return nil
}

// errNotRunning — двигать нечего, клиент не запущен.
var errNotRunning = errors.New("клиент не запущен")

// live — сколько потоков на учёте прямо сейчас. Для тестов.
func (c *Control) live() int {
	if c == nil || c.streams == nil {
		return 0
	}
	c.streams.mu.Lock()
	defer c.streams.mu.Unlock()
	return len(c.streams.live)
}
