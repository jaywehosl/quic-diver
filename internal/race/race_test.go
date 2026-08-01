package race

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// peer — сосед, отвечающий с заданной задержкой.
type peer struct {
	id     string
	delay  time.Duration
	answer Kind
	runner *Runner

	mu   sync.Mutex
	sent int
}

func (p *peer) Node() string { return p.id }

func (p *peer) Send(b []byte) error {
	p.mu.Lock()
	p.sent++
	p.mu.Unlock()

	m, err := Decode(b)
	if err != nil {
		return err
	}
	go func() {
		time.Sleep(p.delay)
		p.runner.Reply(Message{Kind: p.answer, Flow: m.Flow}, p.id)
	}()
	return nil
}

func (p *peer) sends() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sent
}

func TestFastestWins(t *testing.T) {
	r := NewRunner()
	slow := &peer{id: "slow", delay: 80 * time.Millisecond, answer: KindTake, runner: r}
	fast := &peer{id: "fast", delay: 5 * time.Millisecond, answer: KindTake, runner: r}

	winner, err := r.Run(context.Background(), []Channel{slow, fast})
	if err != nil {
		t.Fatalf("гонка: %v", err)
	}
	if winner != "fast" {
		t.Fatalf("победил %s, ждали fast", winner)
	}
	// Спрашивают всех сразу — в этом смысл.
	if slow.sends() != 1 || fast.sends() != 1 {
		t.Fatalf("предложение ушло не всем: slow=%d fast=%d", slow.sends(), fast.sends())
	}
}

// Загруженный узел отвечает медленнее и потому проигрывает — ровно то, ради чего гонка и
// затевалась: выбор идёт по живому состоянию, а не по вчерашним замерам.
func TestBusyNodeLosesWithoutBeingMarkedDown(t *testing.T) {
	r := NewRunner()
	busy := &peer{id: "busy", delay: 200 * time.Millisecond, answer: KindTake, runner: r}
	idle := &peer{id: "idle", delay: 10 * time.Millisecond, answer: KindTake, runner: r}

	for i := 0; i < 3; i++ {
		winner, err := r.Run(context.Background(), []Channel{busy, idle})
		if err != nil {
			t.Fatalf("гонка: %v", err)
		}
		if winner != "idle" {
			t.Fatalf("круг %d: победил %s", i, winner)
		}
	}
	// Загруженный сосед по-прежнему опрашивается: он не выведен из строя, просто медленнее.
	if busy.sends() != 3 {
		t.Fatalf("загруженного перестали спрашивать: %d предложений", busy.sends())
	}
}

// Отбирать участников — забота вызывающего: он знает роли из журнала. Гонка спрашивает
// всех, кого ей дали, и никаких признаков у узлов не различает.
func TestEveryGivenPeerIsAsked(t *testing.T) {
	r := NewRunner()
	a := &peer{id: "a", delay: 5 * time.Millisecond, answer: KindTake, runner: r}
	b := &peer{id: "b", delay: 20 * time.Millisecond, answer: KindTake, runner: r}
	c := &peer{id: "c", delay: 30 * time.Millisecond, answer: KindTake, runner: r}

	if _, err := r.Run(context.Background(), []Channel{a, b, c}); err != nil {
		t.Fatalf("гонка: %v", err)
	}
	for _, p := range []*peer{a, b, c} {
		if p.sends() != 1 {
			t.Fatalf("узел %s получил %d предложений", p.id, p.sends())
		}
	}
}

// Отказ не должен заставлять ждать таймаут, если отказались все.
func TestAllPassEndsEarly(t *testing.T) {
	r := NewRunner()
	a := &peer{id: "a", delay: time.Millisecond, answer: KindPass, runner: r}
	b := &peer{id: "b", delay: time.Millisecond, answer: KindPass, runner: r}

	start := time.Now()
	_, err := r.Run(context.Background(), []Channel{a, b})
	if !errors.Is(err, ErrNobodyTook) {
		t.Fatalf("ждали отказ, получили: %v", err)
	}
	if elapsed := time.Since(start); elapsed > Timeout/2 {
		t.Fatalf("досидели до таймаута вместо раннего выхода: %s", elapsed)
	}
}

func TestSilenceEndsWithTimeout(t *testing.T) {
	r := NewRunner()
	mute := &peer{id: "mute", delay: time.Hour, answer: KindTake, runner: r}

	start := time.Now()
	_, err := r.Run(context.Background(), []Channel{mute})
	if !errors.Is(err, ErrNobodyTook) {
		t.Fatalf("ждали отказ, получили: %v", err)
	}
	if elapsed := time.Since(start); elapsed < Timeout {
		t.Fatalf("сдались раньше срока: %s", elapsed)
	}
}

// Выходных узлов в сети нет вовсе — гонка обязана сказать об этом сразу, а не через таймаут.
func TestNoPeersAtAll(t *testing.T) {
	r := NewRunner()

	start := time.Now()
	_, err := r.Run(context.Background(), nil)
	if !errors.Is(err, ErrNobodyTook) {
		t.Fatalf("ждали отказ, получили: %v", err)
	}
	if !strings.Contains(err.Error(), "некого спрашивать") {
		t.Fatalf("непонятная причина: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Millisecond {
		t.Fatalf("ждали впустую %s, хотя спрашивать было некого", elapsed)
	}
}

// Опоздавший отклик не должен ничего ломать: гонка уже закончилась, и его просто нет.
func TestLateReplyIsHarmless(t *testing.T) {
	r := NewRunner()
	fast := &peer{id: "fast", delay: time.Millisecond, answer: KindTake, runner: r}
	late := &peer{id: "late", delay: 50 * time.Millisecond, answer: KindTake, runner: r}

	winner, err := r.Run(context.Background(), []Channel{fast, late})
	if err != nil {
		t.Fatalf("гонка: %v", err)
	}
	if winner != "fast" {
		t.Fatalf("победил %s", winner)
	}
	time.Sleep(80 * time.Millisecond) // опоздавший отвечает уже в пустоту
}

// Выходной узел берёт всё, что ему предлагают: выбирать не из чего, роль уже проверена
// тем, кто предложение прислал.
func TestResponderTakesByDefault(t *testing.T) {
	resp := Responder{}

	answer, err := resp.Answer(Message{Kind: KindOffer, Flow: 7})
	if err != nil {
		t.Fatalf("отклик: %v", err)
	}
	m, err := Decode(answer)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if m.Kind != KindTake || m.Flow != 7 {
		t.Fatalf("отклик неверен: %+v", m)
	}

	if _, err := resp.Answer(Message{Kind: KindTake, Flow: 8}); err == nil {
		t.Fatal("на отклик ответили откликом")
	}
}

func TestResponderCanRefuse(t *testing.T) {
	resp := Responder{Accept: func(uint64) bool { return false }}
	answer, err := resp.Answer(Message{Kind: KindOffer, Flow: 1})
	if err != nil {
		t.Fatalf("отклик: %v", err)
	}
	m, _ := Decode(answer)
	if m.Kind != KindPass {
		t.Fatal("перегруженный узел всё равно взял поток")
	}
}

func TestCodecRoundTrip(t *testing.T) {
	for _, want := range []Message{
		{Kind: KindOffer, Flow: 1},
		{Kind: KindOffer, Flow: 1 << 40},
		{Kind: KindTake, Flow: 42},
		{Kind: KindPass, Flow: 43},
	} {
		raw, err := want.Encode()
		if err != nil {
			t.Fatalf("кодирование %+v: %v", want, err)
		}
		got, err := Decode(raw)
		if err != nil {
			t.Fatalf("разбор %+v: %v", want, err)
		}
		if got.Kind != want.Kind || got.Flow != want.Flow {
			t.Fatalf("сообщение разъехалось: %+v против %+v", got, want)
		}
		if len(raw) != 9 {
			t.Fatalf("сообщение гонки раздулось до %d байт", len(raw))
		}
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := Decode([]byte{1, 2, 3}); !errors.Is(err, ErrShort) {
		t.Fatalf("обрывок принят: %v", err)
	}
	if _, err := Decode([]byte{9, 0, 0, 0, 0, 0, 0, 0, 1}); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("выдуманный вид принят: %v", err)
	}
	// Лишние байты в хвосте не мешают: разбирается ровно то, что определено форматом.
	if _, err := Decode([]byte{byte(KindOffer), 0, 0, 0, 0, 0, 0, 0, 1, 'x', 'y'}); err != nil {
		t.Fatalf("хвост сломал разбор: %v", err)
	}
}
