package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jaywehosl/quic-diver/internal/control"
	"github.com/jaywehosl/quic-diver/internal/link"
	"github.com/jaywehosl/quic-diver/internal/node"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Обновление сведений о сети без работающего клиента.
//
// Работающий клиент сведения и так получает: снапшот приходит по управляющему каналу на каждое
// изменение журнала. Но клиент включён не всегда, а сеть меняется и в его отсутствие — и тогда
// человек узнаёт об этом ровно в тот момент, когда единственный записанный у него узел умер.
//
// Поэтому есть и второй вход, тот же по сути, что у баз geosite: поднять свою связь, забрать
// снапшот, записать, разойтись. Туннель не нужен, разрешение VPN на телефоне не спрашивается.
//
// Так закрывается требование ТЗ ст. 32: клиент сам запрашивает сведения о работающих узлах.

// NetworkStatus — что известно о сети после обновления.
type NetworkStatus struct {
	// Network — имя сети.
	Network string `json:"network"`
	// Nodes — сколько входных узлов теперь известно.
	Nodes int `json:"nodes"`
	// Egress — есть ли в сети выходные узлы.
	Egress bool `json:"egress"`
	// Changed — изменился ли состав по сравнению с тем, что было записано.
	Changed bool `json:"changed"`
	// SavedUnix — когда сведения записаны, в секундах эпохи.
	SavedUnix int64 `json:"saved_unix"`
}

// JSON отдаёт состояние строкой — для моста в приложение.
func (s NetworkStatus) JSON() string {
	raw, err := json.Marshal(s)
	if err != nil {
		return `{"network":""}`
	}
	return string(raw)
}

// LocalNetwork отдаёт то, что записано, никуда не ходя.
//
// Нужно, чтобы экран открылся сразу: связь с узлом стоит секунды, а «когда обновлялись в
// последний раз» известно и так.
func LocalNetwork(dir string, log *slog.Logger) NetworkStatus {
	// Отпечаток не сверяется: ссылки здесь нет, экран открывается до всякого разбора бандла.
	// Сверка случится при первом же применении — и в клиенте, и при обновлении.
	saved, ok := loadRemembered(dir, oplog.Fingerprint{}, log)
	if !ok {
		return NetworkStatus{}
	}
	return NetworkStatus{
		Network:   saved.Network,
		Nodes:     len(saved.Nodes),
		Egress:    saved.Egress,
		SavedUnix: saved.SavedUnix,
	}
}

// RefreshNetwork забирает у сети свежие сведения и записывает их.
//
// Связь поднимается своя и закрывается по возвращении. Вызывать при работающем клиенте не надо:
// он получает то же самое сам и без спроса.
func RefreshNetwork(ctx context.Context, o Options) (NetworkStatus, error) {
	o = o.withDefaults()

	log := o.Log
	if log == nil {
		log = newLogger(o.LogLevel)
	}

	net, err := resolveNetwork(o, log)
	if err != nil {
		return NetworkStatus{}, err
	}
	// Идём по тому, что записано с прошлого раза: узлы из ссылки могли умереть все до одного,
	// а записанные — это те, что сеть считала живыми последними.
	if saved, ok := loadRemembered(o.StateDir, net.genesis, log); ok {
		net.targets = saved.targets()
	}

	conn, err := link.New(link.Config{
		Targets:   net.targets,
		TLS:       &tls.Config{},
		Self:      net.self,
		OnConnect: func(c *node.Conn) { c.SetLog(log) },
		Log:       log,
	})
	if err != nil {
		return NetworkStatus{}, err
	}

	linkCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() { _ = conn.Run(linkCtx) }()

	first, err := waitFirst(ctx, conn)
	if err != nil {
		return NetworkStatus{}, fmt.Errorf("связи с сетью нет: %w", err)
	}

	// Снапшот узел отдаёт сам, первым же кадром после приветствия, — ждать и просить не нужно.
	// Срок нужен на случай, если на том конце версия, которая этого ещё не умеет: висеть на
	// чтении вечно клиент не должен.
	snapCtx, cancel := context.WithTimeout(ctx, snapshotWait)
	defer cancel()

	snap, err := firstSnapshot(snapCtx, first)
	if err != nil {
		return NetworkStatus{}, err
	}
	if !net.genesis.IsZero() && snap.Genesis != net.genesis {
		return NetworkStatus{}, fmt.Errorf("узел %s отдал снапшот чужой сети", first.Peer().ID)
	}
	if len(snap.Nodes) == 0 {
		return NetworkStatus{}, fmt.Errorf("узел %s не назвал ни одного входного узла", first.Peer().ID)
	}

	before, _ := loadRemembered(o.StateDir, net.genesis, log)
	memory := &networkMemory{dir: o.StateDir, genesis: net.genesis, known: before}
	memory.apply(snap, log)

	return NetworkStatus{
		Network:   memory.known.Network,
		Nodes:     len(memory.known.Nodes),
		Egress:    memory.known.Egress,
		Changed:   memory.known.SavedUnix != before.SavedUnix,
		SavedUnix: memory.known.SavedUnix,
	}, nil
}

// snapshotWait — сколько ждать снапшота от узла, который уже поздоровался.
const snapshotWait = 20 * time.Second

// firstSnapshot читает первый снапшот из управляющего потока.
func firstSnapshot(ctx context.Context, conn *node.Conn) (control.Snapshot, error) {
	type result struct {
		snap control.Snapshot
		err  error
	}
	done := make(chan result, 1)

	go func() {
		for {
			frame, err := control.ReadFrame(conn.Stream())
			if err != nil {
				done <- result{err: fmt.Errorf("чтение снапшота: %w", err)}
				return
			}
			if frame.Kind != control.KindSnapshot {
				continue
			}
			snap, err := control.ReadSnapshot(frame.Payload)
			done <- result{snap: snap, err: err}
			return
		}
	}()

	select {
	case r := <-done:
		return r.snap, r.err
	case <-ctx.Done():
		return control.Snapshot{}, fmt.Errorf("узел не прислал снапшот: %w", ctx.Err())
	}
}
