package mesh

import (
	"context"
	"fmt"
	"io"

	"github.com/jaywehosl/quic-diver/internal/node"
	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/race"
)

// Живые связи и гонка по ним.
//
// Связь считается годной для гонки, когда у неё есть и соединение, и открытый канал
// датаграмм. Пока канал не открыт, узел в гонках не участвует — молчащий участник хуже
// отсутствующего: он заставляет ждать себя до таймаута.

// live — установленная связь с соседом.
type live struct {
	node    oplog.Node
	conn    *node.Conn
	channel *node.RaceChannel
}

// Send отправляет датаграмму гонки. Реализует race.Channel.
func (l *live) Send(b []byte) error { return l.channel.Send(b) }

// Node — идентификатор соседа.
func (l *live) Node() string { return l.node.ID }

// Open открывает поток до адреса через этого соседа. Реализует node.Exit.
//
// Имя клиента едет вместе с потоком: сокет наружу откроет сосед, ему и считать байты, а
// клиента он не знает (решение 001 §2).
func (l *live) Open(ctx context.Context, target, client string) (io.ReadWriteCloser, error) {
	return l.conn.OpenFor(ctx, target, false, client)
}

// OpenUDP открывает пакетный путь до адреса через этого соседа. Реализует node.Exit.
//
// Дальше сосед уже никого не пересылает: цепочка вход → выход → наружу одна и та же и для
// потоков, и для датаграмм, и удлинять её незачем.
func (l *live) OpenUDP(ctx context.Context, target, client string) (io.ReadWriteCloser, error) {
	return l.conn.OpenUDPFor(ctx, target, false, client)
}

// addLive заносит связь в список живых.
func (m *Mesh) addLive(l *live) func() {
	m.liveMu.Lock()
	m.liveLinks[l.node.ID] = l
	m.liveMu.Unlock()

	return func() {
		m.liveMu.Lock()
		if cur, ok := m.liveLinks[l.node.ID]; ok && cur == l {
			delete(m.liveLinks, l.node.ID)
		}
		m.liveMu.Unlock()
	}
}

// Pick выбирает выходной узел гонкой. Реализует node.ExitPicker.
//
// Отбор один: роль. Никаких стран и площадок — сеть балансируется гонкой, и какой из
// выходных узлов лучше прямо сейчас, знает только отклик.
func (m *Mesh) Pick(ctx context.Context) (node.Exit, error) {
	m.liveMu.RLock()
	channels := make([]race.Channel, 0, len(m.liveLinks))
	byID := make(map[string]*live, len(m.liveLinks))
	for id, l := range m.liveLinks {
		if !l.node.HasRole(oplog.RoleEgress) {
			continue
		}
		channels = append(channels, l)
		byID[id] = l
	}
	m.liveMu.RUnlock()

	winner, err := m.runner.Run(ctx, channels)
	if err != nil {
		return nil, err
	}

	l, ok := byID[winner]
	if !ok {
		// Победитель успел отвалиться между откликом и выбором. Бывает, и обрабатывается
		// как обычный отказ: вызывающий выпустит поток у себя.
		return nil, fmt.Errorf("%w: узел %s исчез сразу после отклика", race.ErrNobodyTook, winner)
	}
	return l, nil
}

// OnRace отвечает на предложение гонки. Вызывается со стороны выходного узла.
func (m *Mesh) OnRace(from string, msg []byte) ([]byte, error) {
	parsed, err := race.Decode(msg)
	if err != nil {
		return nil, err
	}

	switch parsed.Kind {
	case race.KindTake, race.KindPass:
		// Это отклик на нашу гонку, пришедший по каналу, который сосед поднял к нам.
		m.runner.Reply(parsed, from)
		return nil, nil

	case race.KindOffer:
		me, ok := m.cfg.Store.State().Node(m.cfg.Self.ID)
		if !ok || !me.HasRole(oplog.RoleEgress) {
			// Не наше дело: узел не выходной. Отвечаем отказом, чтобы спрашивающий не ждал.
			return race.Message{Kind: race.KindPass, Flow: parsed.Flow}.Encode()
		}
		return race.Responder{}.Answer(parsed)

	default:
		return nil, fmt.Errorf("mesh: непонятное сообщение гонки %s", parsed.Kind)
	}
}
