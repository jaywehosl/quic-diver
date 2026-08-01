package main

import (
	"context"
	"log/slog"

	"github.com/jaywehosl/quic-diver/internal/config"
	"github.com/jaywehosl/quic-diver/internal/node"
	"github.com/jaywehosl/quic-diver/internal/store"
)

// watchRate следит за потолками в журнале и разносит их по живым соединениям.
//
// Раньше новое число доходило до узла только перезапуском службы — а перезапуск рвёт все
// соединения разом: трафик всех клиентов падает ради двух байт в журнале. Решение 002 требует
// обратного: параметры приходят журналом и меняются на лету.
//
// Меша это касается тоже, и там даже проще: связи между узлами держит сам узел, они постоянные
// и трафика клиентов по ним может не идти вовсе. Новое число применяется к ним следующей же
// сверкой — mesh спрашивает журнал на каждый набор.
func watchRate(ctx context.Context, st *store.Store, n *node.Node, cfg config.Node, log *slog.Logger) {
	applied := brutalDown(cfg, st)

	for {
		// Канал берётся до снимка: наоборот было бы окном, в которое правка проскакивает
		// незамеченной.
		changed := st.Changed()

		if want := brutalDown(cfg, st); want != applied {
			touched := n.SetSendMbps(want)
			log.Info("потолок отправки клиентам изменён",
				"было_мбит", applied, "стало_мбит", want, "соединений", touched)
			applied = want
		}

		select {
		case <-changed:
		case <-ctx.Done():
			return
		}
	}
}
