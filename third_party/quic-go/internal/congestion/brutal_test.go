package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

// Правка форка QUIC Diver: проверки алгоритма BRUTAL (решение 006).

const (
	testRateMbps  = 100
	testRate      = Bandwidth(testRateMbps) * 1e6 * BitsPerSecond
	testRTT       = 50 * time.Millisecond
	testMaxPacket = protocol.ByteCount(1200)
)

func newTestBrutal(t *testing.T) (*brutalSender, *mockClock, *utils.RTTStats) {
	t.Helper()
	clock := mockClock(0)
	// Часы стартуют с нуля, а нулевое время означает «ещё не считали». Двигаем вперёд.
	clock.Advance(time.Second)

	rtt := utils.NewRTTStats()
	rtt.UpdateRTT(testRTT, 0)

	return NewBrutalSender(&clock, rtt, testMaxPacket, testRate), &clock, rtt
}

// Окно — произведение заданной скорости на задержку. Ничего измерять для этого не нужно.
func TestBrutalWindowIsRateTimesDelay(t *testing.T) {
	b, _, _ := newTestBrutal(t)

	// 100 Мбит/с — это 12,5 МБ/с; за 50 мс это 625 000 байт.
	require.InDelta(t, 625_000, int(b.GetCongestionWindow()), 1000)
}

// Задержка выросла — окно выросло вместе с ней, иначе канал простаивает.
func TestBrutalWindowFollowsDelay(t *testing.T) {
	b, _, rtt := newTestBrutal(t)
	before := b.GetCongestionWindow()

	rtt.UpdateRTT(4*testRTT, 0)
	require.Greater(t, int(b.GetCongestionWindow()), int(before))
}

// Главное свойство: потери окно не уменьшают. Обычный алгоритм здесь срезал бы его вдвое.
func TestBrutalDoesNotShrinkOnLoss(t *testing.T) {
	b, _, _ := newTestBrutal(t)
	before := b.GetCongestionWindow()

	for range 20 {
		b.OnCongestionEvent(0, testMaxPacket, 0)
	}
	require.GreaterOrEqual(t, int(b.GetCongestionWindow()), int(before))
	require.False(t, b.InRecovery())
	require.False(t, b.InSlowStart())
}

// Потери компенсируются: доезжает меньше — шлём больше, чтобы полезная скорость осталась
// заданной.
func TestBrutalCompensatesForLoss(t *testing.T) {
	b, _, _ := newTestBrutal(t)
	clean := b.GetCongestionWindow()

	// Четыре из пяти доехали: компенсация должна быть примерно на четверть.
	for range 80 {
		b.OnPacketAcked(0, testMaxPacket, 0, b.clock.Now())
	}
	for range 20 {
		b.OnCongestionEvent(0, testMaxPacket, 0)
	}

	got := b.GetCongestionWindow()
	require.InDelta(t, float64(clean)/0.8, float64(got), float64(clean)*0.02)
}

// Компенсация ограничена: линия, теряющая почти всё, не должна давать бесконечное окно.
func TestBrutalCompensationIsBounded(t *testing.T) {
	b, _, _ := newTestBrutal(t)
	clean := b.GetCongestionWindow()

	// Доезжает один пакет из ста.
	b.OnPacketAcked(0, testMaxPacket, 0, b.clock.Now())
	for range 99 {
		b.OnCongestionEvent(0, testMaxPacket, 0)
	}

	got := float64(b.GetCongestionWindow())
	require.LessOrEqual(t, got, float64(clean)/brutalMinAckRate*1.01)
}

// Окно учёта скользит: беда, случившаяся давно, на сегодняшнюю отправку не влияет.
func TestBrutalForgetsOldLosses(t *testing.T) {
	b, clock, _ := newTestBrutal(t)
	clean := b.GetCongestionWindow()

	for range 50 {
		b.OnCongestionEvent(0, testMaxPacket, 0)
	}
	require.Greater(t, int(b.GetCongestionWindow()), int(clean))

	// Пережидаем всё окно учёта целиком.
	clock.Advance(brutalSlots * brutalSlotDuration * 2)
	require.Equal(t, int(clean), int(b.GetCongestionWindow()))
}

// На быстрой линии с крошечной задержкой окно не должно схлопнуться до нуля.
func TestBrutalKeepsMinimumWindow(t *testing.T) {
	clock := mockClock(0)
	clock.Advance(time.Second)
	rtt := utils.NewRTTStats()
	rtt.UpdateRTT(time.Microsecond, 0)

	b := NewBrutalSender(&clock, rtt, testMaxPacket, 1*1e6*BitsPerSecond)
	require.Equal(t, int(brutalMinWindowPackets*testMaxPacket), int(b.GetCongestionWindow()))
}

// Пока задержка не измерена, окно всё равно осмысленное: слать надо с первого пакета.
func TestBrutalWorksBeforeFirstRTT(t *testing.T) {
	clock := mockClock(0)
	clock.Advance(time.Second)

	b := NewBrutalSender(&clock, utils.NewRTTStats(), testMaxPacket, testRate)
	require.Greater(t, int(b.GetCongestionWindow()), int(brutalMinWindowPackets*testMaxPacket))
	require.True(t, b.CanSend(0))
}

// Отправка ограничивается окном, а не благими намерениями.
func TestBrutalStopsAtTheWindow(t *testing.T) {
	b, _, _ := newTestBrutal(t)
	cwnd := b.GetCongestionWindow()

	require.True(t, b.CanSend(cwnd-1))
	require.False(t, b.CanSend(cwnd))
	require.False(t, b.CanSend(cwnd+1))
}

// Темп задаётся заданной скоростью: пейсер выдаёт бюджет и требует ждать, когда он кончился.
func TestBrutalPacesAtTheGivenRate(t *testing.T) {
	b, clock, _ := newTestBrutal(t)

	require.True(t, b.HasPacingBudget(clock.Now()))

	// Тратим бюджет целиком.
	for range 100 {
		b.OnPacketSent(clock.Now(), 0, 0, testMaxPacket, true)
	}
	require.False(t, b.HasPacingBudget(clock.Now()))

	// За десять миллисекунд на ста мегабитах набегает 125 000 байт — с запасом.
	clock.Advance(10 * time.Millisecond)
	require.True(t, b.HasPacingBudget(clock.Now()))
}

// Пакеты, не требующие подтверждения, темп не расходуют.
func TestBrutalIgnoresNonRetransmittable(t *testing.T) {
	b, clock, _ := newTestBrutal(t)

	for range 100 {
		b.OnPacketSent(clock.Now(), 0, 0, testMaxPacket, false)
	}
	require.True(t, b.HasPacingBudget(clock.Now()))
}
