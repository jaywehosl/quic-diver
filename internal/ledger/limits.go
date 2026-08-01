package ledger

import (
	"fmt"
	"time"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Проверка лимитов (решение 001 §2).
//
// Лимиты мягкие, и это не оговорка. Узлы разносят расход раз в несколько секунд, поэтому в
// окне между обменами клиент может перебрать — и переберёт. Взамен соблюдается правило,
// которое важнее точности: **недоступность соседей никогда не отказ клиенту.** Узел,
// потерявший связь с сетью, продолжает обслуживать по последней известной картине, а не
// закрывается на всякий случай.

// Verdict — что решено про клиента.
type Verdict struct {
	// Allowed — пускать ли.
	Allowed bool
	// Reason — почему нет. Пусто, когда пускаем.
	Reason string
}

func allowed() Verdict { return Verdict{Allowed: true} }

func refused(format string, args ...any) Verdict {
	return Verdict{Reason: fmt.Sprintf(format, args...)}
}

// Check решает, пускать ли клиента и его устройство.
//
// device — как устройство себя называет; пустое означает, что клиент не назвался, и тогда
// лимит устройств посчитать нечем.
func (l *Ledger) Check(c oplog.Client, device, addr string, at time.Time) Verdict {
	if c.Suspended {
		return refused("клиент приостановлен")
	}
	if c.ExpiresAt != nil && at.After(*c.ExpiresAt) {
		return refused("срок клиента истёк %s", c.ExpiresAt.UTC().Format(time.DateOnly))
	}

	if c.Limits.TrafficBytes > 0 {
		period := PeriodOf(c.Limits.TrafficPeriod, at)
		if spent := l.Total(c.ID, period).Total(); spent >= uint64(c.Limits.TrafficBytes) {
			return refused("потрачено %.2f ГБ из %.2f ГБ",
				gigabytes(spent), gigabytes(uint64(c.Limits.TrafficBytes)))
		}
	}

	// Устройство, уже работающее, лимита не занимает второй раз: переподключение к другому
	// узлу — обычное дело, и считать его новым устройством значило бы выгонять человека при
	// каждой смене сети.
	if c.Limits.Devices > 0 && device != "" && !l.knows(c.ID, device) {
		if n := l.Devices(c.ID); n >= c.Limits.Devices {
			return refused("устройств уже %d из %d", n, c.Limits.Devices)
		}
	}

	if c.Limits.Addrs > 0 && addr != "" && !l.knowsAddr(c.ID, addr) {
		if n := l.Addrs(c.ID); n >= c.Limits.Addrs {
			return refused("адресов уже %d из %d", n, c.Limits.Addrs)
		}
	}

	return allowed()
}

// knows говорит, работает ли это устройство прямо сейчас.
func (l *Ledger) knows(client, device string) bool {
	for _, s := range l.Sessions(client) {
		if s.Device == device {
			return true
		}
	}
	return false
}

func (l *Ledger) knowsAddr(client, addr string) bool {
	for _, s := range l.Sessions(client) {
		if s.Addr == addr {
			return true
		}
	}
	return false
}

func gigabytes(b uint64) float64 { return float64(b) / (1 << 30) }
