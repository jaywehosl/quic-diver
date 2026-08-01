package mobile

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
)

// level — порог журнала, общий на всё ядро.
//
// Отдельно от handler и атомарный, потому что переключается при работающем клиенте: человек
// упирается в непонятное поведение и включает подробности прямо тогда, когда оно происходит.
// Требовать ради этого переподключения означало бы просить его воспроизвести всё заново.
var level atomic.Int32

func init() { level.Store(int32(slog.LevelInfo)) }

// SetVerbose переключает подробность журнала.
//
// Подробный журнал показывает каждый поток: куда пошёл, через выход или нет, по какому
// правилу. Обычный об этом молчит — иначе при открытой странице новостей журнал за минуту
// уходит на сотни строк.
func SetVerbose(on bool) {
	if on {
		level.Store(int32(slog.LevelDebug))
		return
	}
	level.Store(int32(slog.LevelInfo))
}

// Verbose говорит, включён ли подробный журнал.
func Verbose() bool { return slog.Level(level.Load()) == slog.LevelDebug }

// handler — приёмник журнала, отдающий строки приложению.
//
// Своя реализация, а не slog.NewTextHandler в буфер: на телефоне журнал читает человек, а не
// программа, и ему нужна строка вида «сообщение: поле=значение», а не машинный формат с
// временем в наносекундах.
type handler struct {
	attrs []slog.Attr
	group string
}

func newHandler() *handler { return &handler{} }

// Enabled смотрит на общий порог, а не на свой: тот меняется на ходу, и обработчик,
// запомнивший уровень при создании, остался бы глухим до перезапуска клиента.
func (h *handler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= slog.Level(level.Load())
}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder

	switch {
	case r.Level >= slog.LevelError:
		b.WriteString("ошибка: ")
	case r.Level >= slog.LevelWarn:
		b.WriteString("внимание: ")
	}
	b.WriteString(r.Message)

	write := func(a slog.Attr) {
		b.WriteString(" ")
		if h.group != "" {
			b.WriteString(h.group)
			b.WriteString(".")
		}
		b.WriteString(a.Key)
		b.WriteString("=")
		fmt.Fprint(&b, a.Value.Any())
	}
	for _, a := range h.attrs {
		write(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		write(a)
		return true
	})

	emit(b.String())
	return nil
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	next.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &next
}

func (h *handler) WithGroup(name string) slog.Handler {
	next := *h
	next.group = name
	return &next
}
