package node

import (
	"context"
	"fmt"
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

// RacePath — путь канала гонки.
//
// Как и управляющий, он не секрет: посторонний, попавший сюда, получает ту же страницу, что
// и на любом другом адресе. Стойкость держится на приветствии, а не на незнании пути.
const RacePath = "/qd/v1/race"

// RaceChannel — канал гонки к соседу.
//
// Живёт поверх отдельного запроса: датаграммы RFC 9297 привязаны к потоку, а поток журнала
// занят обменом и его такт сбивать нельзя.
type RaceChannel struct {
	stream *http3.RequestStream
}

// Send отправляет датаграмму.
func (c *RaceChannel) Send(b []byte) error { return c.stream.SendDatagram(b) }

// Receive ждёт датаграмму.
func (c *RaceChannel) Receive(ctx context.Context) ([]byte, error) {
	return c.stream.ReceiveDatagram(ctx)
}

// Close закрывает канал.
func (c *RaceChannel) Close() error { return c.stream.Close() }

// OpenRace поднимает канал гонки к узлу.
func (c *Conn) OpenRace(ctx context.Context, authority string) (*RaceChannel, error) {
	stream, err := c.http3.OpenRequestStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("node: открытие канала гонки: %w", err)
	}

	// Здесь пустое тело как раз кстати: по каналу гонки едут только датаграммы, и
	// content-length: 0 говорит чистую правду.
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx),
		http.MethodGet, "https://"+authority+RacePath, nil)
	if err != nil {
		return nil, fmt.Errorf("node: сборка запроса гонки: %w", err)
	}
	if err := stream.SendRequestHeader(req); err != nil {
		return nil, fmt.Errorf("node: отправка заголовков гонки: %w", err)
	}
	resp, err := stream.ReadResponse()
	if err != nil {
		return nil, fmt.Errorf("node: ответ на запрос гонки: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("node: узел отказал в канале гонки: %s", resp.Status)
	}
	return &RaceChannel{stream: stream}, nil
}

// serveRace обслуживает канал гонки со стороны выходного узла.
func (n *Node) serveRace(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		n.reject(w, r, "нет состояния TLS")
		return
	}
	binding, err := bindingOf(r)
	if err != nil {
		n.reject(w, r, "нет привязки к сессии")
		return
	}
	peer, ok := n.sessions.lookup(binding)
	if !ok {
		n.reject(w, r, "соединение не проходило приветствия")
		return
	}
	if n.cfg.OnRace == nil {
		n.reject(w, r, "узел не участвует в гонках")
		return
	}

	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		n.reject(w, r, "поток не захватывается")
		return
	}

	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	stream := streamer.HTTPStream()
	defer stream.Close()

	n.log.Debug("канал гонки открыт", "peer", peer.ID)
	for {
		msg, err := stream.ReceiveDatagram(r.Context())
		if err != nil {
			n.log.Debug("канал гонки закрыт", "peer", peer.ID, "err", err)
			return
		}
		answer, err := n.cfg.OnRace(peer.ID, msg)
		if err != nil {
			n.log.Debug("предложение не понято", "peer", peer.ID, "err", err)
			continue
		}
		if answer == nil {
			continue
		}
		if err := stream.SendDatagram(answer); err != nil {
			n.log.Debug("отклик не ушёл", "peer", peer.ID, "err", err)
			return
		}
	}
}
