package race

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Timeout — сколько входной узел ждёт первого отклика.
//
// Величина взята из природы задачи: связи тёплые, отклик стоит один RTT, и между
// европейскими и российскими площадками это десятки миллисекунд. Полсекунды — это уже
// «никто не жив», а не «кто-то задумался».
const Timeout = 500 * time.Millisecond

// Channel — канал гонки к одному соседу.
//
// За ним стоит поток запроса с датаграммами (RFC 9297). Отдельный интерфейс нужен затем,
// чтобы гонку можно было проверить без сети.
type Channel interface {
	// Send отправляет датаграмму соседу.
	Send([]byte) error
	// Node — идентификатор соседа, для журнала и для ответа.
	Node() string
}

// ErrNobodyTook означает, что никто не откликнулся.
//
// Это не поломка, а обычное состояние сети, у которого есть запасной путь: поток выпускается
// на самом входном узле. Связь важнее страны — но клиенту об этом сообщают, чтобы он не
// думал, будто сидит в Варшаве, находясь в Москве.
var ErrNobodyTook = errors.New("race: никто не взял поток")

// Runner ведёт гонки на стороне входного узла.
type Runner struct {
	mu      sync.Mutex
	pending map[uint64]chan string
	flow    atomic.Uint64
}

// NewRunner создаёт бегуна.
func NewRunner() *Runner {
	return &Runner{pending: make(map[uint64]chan string)}
}

// Run объявляет гонку среди переданных соседей и возвращает того, кто откликнулся первым.
//
// Отбирать соседей — забота вызывающего: он знает роли из журнала. Здесь спрашивают всех,
// кого дали, и берут первого ответившего.
func (r *Runner) Run(ctx context.Context, channels []Channel) (string, error) {
	flow := r.flow.Add(1)

	replies := make(chan string, len(channels))
	r.mu.Lock()
	r.pending[flow] = replies
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.pending, flow)
		r.mu.Unlock()
	}()

	msg, err := Message{Kind: KindOffer, Flow: flow}.Encode()
	if err != nil {
		return "", err
	}

	sent := 0
	for _, ch := range channels {
		if err := ch.Send(msg); err != nil {
			// Один недоступный сосед не отменяет гонку: смысл её в том и состоит, что
			// спрашивают всех сразу.
			continue
		}
		sent++
	}
	if sent == 0 {
		return "", fmt.Errorf("%w: некого спрашивать", ErrNobodyTook)
	}

	timer := time.NewTimer(Timeout)
	defer timer.Stop()

	passes := 0
	for {
		select {
		case node := <-replies:
			if node == "" {
				// Отказ. Ждём остальных, пока есть кого ждать.
				passes++
				if passes >= sent {
					return "", fmt.Errorf("%w: все %d отказались", ErrNobodyTook, sent)
				}
				continue
			}
			return node, nil
		case <-timer.C:
			return "", fmt.Errorf("%w: никто не ответил за %s", ErrNobodyTook, Timeout)
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

// Reply принимает отклик соседа.
//
// Отклик на гонку, которая уже завершилась, отбрасывается молча: победитель определён, и
// опоздавшему просто ничего не достаётся. Ошибкой это не является — так гонка и устроена.
func (r *Runner) Reply(m Message, node string) {
	r.mu.Lock()
	replies, ok := r.pending[m.Flow]
	r.mu.Unlock()
	if !ok {
		return
	}

	switch m.Kind {
	case KindTake:
		select {
		case replies <- node:
		default:
		}
	case KindPass:
		select {
		case replies <- "":
		default:
		}
	}
}

// Responder отвечает на предложения на стороне выходного узла.
type Responder struct {
	// Accept решает, берём ли поток. Пустой означает «берём всегда».
	//
	// Через него узел отказывается, когда ему нечем взять поток — кончились дескрипторы,
	// упёрся в потолок. Отказ честнее молчания: спрашивающий не станет ждать таймаута.
	Accept func(flow uint64) bool
}

// Answer готовит отклик на предложение.
func (r Responder) Answer(m Message) ([]byte, error) {
	if m.Kind != KindOffer {
		return nil, fmt.Errorf("race: на %s отвечать нечем", m.Kind)
	}

	take := true
	if r.Accept != nil {
		take = r.Accept(m.Flow)
	}

	kind := KindPass
	if take {
		kind = KindTake
	}
	return Message{Kind: kind, Flow: m.Flow}.Encode()
}
