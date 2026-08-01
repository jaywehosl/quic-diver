package congestion

import (
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

// BRUTAL — контроль перегрузки с заданной скоростью (QUIC Diver, решение 006).
//
// Обычные алгоритмы трактуют потерю пакета как «нас слишком много» и режут скорость. На линии,
// где потери идут постоянно и без всякой связи с нашей нагрузкой, скорость после этого уже не
// поднимается, хотя канал свободен.
//
// BRUTAL исходит из обратного: скорость задаёт человек, знающий свой канал, а потери — шум,
// который надо перекрыть. Окно считается как произведение заданной скорости на задержку,
// делённое на долю доехавших пакетов.
//
// Отклонение от RFC 9002 §7 здесь осознанное и описано в docs/decisions/006-brutal.md:
// алгоритм не реагирует на потери снижением скорости. Ответственность за то, чтобы потолок
// соответствовал реальному каналу, лежит на администраторе сети.

const (
	// brutalSlotDuration — шаг скользящего окна учёта потерь.
	brutalSlotDuration = 100 * time.Millisecond
	// brutalSlots — сколько шагов помним. Полсекунды: мгновенная доля скакала бы от одного
	// пакета, а окно в минуту не заметило бы, что линия испортилась.
	brutalSlots = 5

	// brutalMinAckRate — нижняя граница доли доехавших при расчёте компенсации.
	//
	// Без неё линия, теряющая почти всё, дала бы бесконечное окно: попытку залить умирающий
	// канал, от которой хуже всем и в первую очередь нам.
	brutalMinAckRate = 0.6

	// brutalMinWindowPackets — окно не может быть меньше: иначе на быстрой линии с крошечным
	// RTT отправка встала бы совсем.
	brutalMinWindowPackets = 4

	// brutalInitialRTT — чем считаем окно, пока задержка не измерена.
	brutalInitialRTT = 100 * time.Millisecond
)

// brutalSender шлёт с заданной скоростью, не снижая её при потерях.
type brutalSender struct {
	rttStats *utils.RTTStats
	pacer    *pacer
	clock    Clock

	// rate — заданная скорость отправки.
	//
	// Атомарная, потому что читают и пишут её разные горутины: читает отправляющая — на каждый
	// такт пейсера и при пересчёте окна, — а пишет управляющая, когда владелец сети поменял
	// потолок. Менять его перезапуском узла нельзя: перезапуск рвёт все живые соединения, то
	// есть роняет трафик всех клиентов ради числа, которое меняется парой байт.
	rate atomic.Uint64

	maxDatagramSize protocol.ByteCount

	// Скользящее окно учёта: сколько пакетов доехало и сколько потерялось.
	slots     [brutalSlots]brutalSlot
	slotStart monotime.Time
	slotIndex int
}

// brutalSlot — учёт за один шаг окна.
type brutalSlot struct {
	acked uint64
	lost  uint64
}

var _ SendAlgorithm = &brutalSender{}
var _ SendAlgorithmWithDebugInfos = &brutalSender{}
var _ RateSetter = &brutalSender{}

// RateSetter — контроллер, которому скорость задают, а не измеряют (QUIC Diver).
//
// Отдельный интерфейс, потому что обычные алгоритмы такого не умеют и уметь не должны: у них
// скорость — результат наблюдения за сетью, и приказать ей нельзя.
type RateSetter interface {
	// SetRate меняет заданную скорость отправки на живом соединении.
	SetRate(Bandwidth)
	// Rate — действующая скорость.
	Rate() Bandwidth
}

// NewBrutalSender собирает отправителя с заданной скоростью в битах в секунду.
func NewBrutalSender(
	clock Clock,
	rttStats *utils.RTTStats,
	initialMaxDatagramSize protocol.ByteCount,
	rate Bandwidth,
) *brutalSender {
	b := &brutalSender{
		rttStats:        rttStats,
		clock:           clock,
		maxDatagramSize: initialMaxDatagramSize,
		slotStart:       clock.Now(),
	}
	b.rate.Store(uint64(rate))
	// Пейсеру нужна только скорость, и у нас она известна заранее — измерять нечего.
	// Читается она через замыкание на каждом такте, поэтому смена скорости действует сразу.
	b.pacer = newPacer(b.Rate)
	b.pacer.SetMaxDatagramSize(initialMaxDatagramSize)
	return b
}

// Rate — заданная скорость отправки.
func (b *brutalSender) Rate() Bandwidth { return Bandwidth(b.rate.Load()) }

// SetRate меняет скорость отправки на живом соединении.
//
// Окно перестроится на следующем пересчёте, то есть в пределах одного RTT; пейсер подхватит
// новое значение с ближайшего такта. Разрывать соединение или пересобирать контроллер не нужно
// вовсе — вся скорость держится на этом одном числе.
func (b *brutalSender) SetRate(rate Bandwidth) {
	if rate > 0 {
		b.rate.Store(uint64(rate))
	}
}

func (b *brutalSender) TimeUntilSend(protocol.ByteCount) monotime.Time {
	return b.pacer.TimeUntilSend()
}

func (b *brutalSender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *brutalSender) OnPacketSent(
	sentTime monotime.Time,
	_ protocol.ByteCount,
	_ protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool,
) {
	if !isRetransmittable {
		return
	}
	b.pacer.SentPacket(sentTime, bytes)
}

func (b *brutalSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

// MaybeExitSlowStart ничего не делает: медленного старта здесь нет вовсе. Скорость известна
// с первого пакета, разгоняться не к чему.
func (b *brutalSender) MaybeExitSlowStart() {}

func (b *brutalSender) OnPacketAcked(
	_ protocol.PacketNumber,
	_ protocol.ByteCount,
	_ protocol.ByteCount,
	eventTime monotime.Time,
) {
	b.rotate(eventTime)
	b.slots[b.slotIndex].acked++
}

// OnCongestionEvent считает потерю — и только. Окно от неё не уменьшается: в этом весь смысл
// алгоритма.
func (b *brutalSender) OnCongestionEvent(
	_ protocol.PacketNumber,
	_ protocol.ByteCount,
	_ protocol.ByteCount,
) {
	b.rotate(b.clock.Now())
	b.slots[b.slotIndex].lost++
}

// OnRetransmissionTimeout ничего не меняет. Таймаут для обычного алгоритма — сигнал, что
// сеть перегружена; здесь он означает лишь, что пакеты не доехали, а это уже учтено потерями.
func (b *brutalSender) OnRetransmissionTimeout(bool) {}

func (b *brutalSender) SetMaxDatagramSize(s protocol.ByteCount) {
	b.maxDatagramSize = s
	b.pacer.SetMaxDatagramSize(s)
}

// InSlowStart — медленного старта нет.
func (b *brutalSender) InSlowStart() bool { return false }

// InRecovery — восстановления нет: снижать нечего.
func (b *brutalSender) InRecovery() bool { return false }

// GetCongestionWindow считает, сколько байт держим в пути.
func (b *brutalSender) GetCongestionWindow() protocol.ByteCount {
	rtt := b.rttStats.SmoothedRTT()
	if rtt <= 0 {
		rtt = brutalInitialRTT
	}

	// Произведение полосы на задержку: столько байт должно быть в пути, чтобы канал не
	// простаивал.
	bytesPerSecond := float64(b.Rate() / BytesPerSecond)
	window := bytesPerSecond * rtt.Seconds() / b.ackRate()

	cwnd := protocol.ByteCount(window)
	if minimum := brutalMinWindowPackets * b.maxDatagramSize; cwnd < minimum {
		return minimum
	}
	return cwnd
}

// ackRate — доля доехавших пакетов за скользящее окно.
func (b *brutalSender) ackRate() float64 {
	b.rotate(b.clock.Now())

	var acked, lost uint64
	for _, s := range b.slots {
		acked += s.acked
		lost += s.lost
	}
	total := acked + lost
	// Пока статистики нет, компенсировать нечего.
	if total == 0 {
		return 1
	}

	rate := float64(acked) / float64(total)
	if rate < brutalMinAckRate {
		return brutalMinAckRate
	}
	return rate
}

// rotate сдвигает скользящее окно, вычищая устаревшие шаги.
func (b *brutalSender) rotate(now monotime.Time) {
	if b.slotStart.IsZero() {
		b.slotStart = now
		return
	}

	steps := int(now.Sub(b.slotStart) / brutalSlotDuration)
	if steps <= 0 {
		return
	}
	if steps >= brutalSlots {
		// Простой дольше всего окна: помнить нечего.
		b.slots = [brutalSlots]brutalSlot{}
		b.slotIndex = 0
		b.slotStart = now
		return
	}
	for range steps {
		b.slotIndex = (b.slotIndex + 1) % brutalSlots
		b.slots[b.slotIndex] = brutalSlot{}
	}
	b.slotStart = b.slotStart.Add(time.Duration(steps) * brutalSlotDuration)
}
