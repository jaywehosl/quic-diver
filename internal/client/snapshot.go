package client

import (
	"context"
	"io"
	"log/slog"

	"github.com/jaywehosl/quic-diver/internal/control"
	"github.com/jaywehosl/quic-diver/internal/link"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Снапшот сети (решение 005).
//
// Узел отдаёт выжимку из журнала по уже открытому управляющему каналу и присылает новую на
// каждое изменение: узлы сети, параметры, расход клиента.
//
// Правил здесь нет. Они принадлежат человеку и живут у него на устройстве — см. заголовок
// control.Snapshot и пересмотр решения 005 от 2026-07-31.

// watchSnapshots слушает снапшоты, пока жив контекст.
func watchSnapshots(
	ctx context.Context,
	l *link.Link,
	genesis oplog.Fingerprint,
	state *State,
	memory *networkMemory,
	log *slog.Logger,
) {
	for ctx.Err() == nil {
		conn, err := l.Conn(ctx)
		if err != nil {
			return
		}

		// Читаем, пока живо это соединение. Обрыв — не беда: гонка поднимет новое, и снапшот
		// приедет заново от того, с кем связались.
		if err := readSnapshots(conn.Stream(), genesis, state, memory, log); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Debug("поток снапшотов прервался", "err", err)
		}

		// Ждём смерти соединения, чтобы не крутиться вхолостую: пока оно живо, новых
		// снапшотов по нему не будет, а связь сменится только после обрыва.
		select {
		case <-conn.QUIC().Context().Done():
		case <-ctx.Done():
			return
		}
	}
}

func readSnapshots(
	stream io.Reader,
	genesis oplog.Fingerprint,
	state *State,
	memory *networkMemory,
	log *slog.Logger,
) error {
	for {
		frame, err := control.ReadFrame(stream)
		if err != nil {
			return err
		}
		if frame.Kind != control.KindSnapshot {
			log.Debug("непонятный кадр на управляющем канале", "kind", frame.Kind.String())
			continue
		}

		snap, err := control.ReadSnapshot(frame.Payload)
		if err != nil {
			return err
		}
		// Снапшот из чужой сети не применяется, даже придя по опознанному каналу: отпечаток
		// генезиса известен из бандла, и расхождение означает, что что-то не то.
		if !genesis.IsZero() && snap.Genesis != genesis {
			log.Error("снапшот из чужой сети, игнорирую",
				"ждали", genesis.String()[:16], "пришёл", snap.Genesis.String()[:16])
			continue
		}

		reportUsage(snap.Usage, log)
		state.FromSnapshot(networkOf(snap), usageOf(snap.Usage))
		memory.apply(snap, log)
	}
}

// networkOf переводит снапшот в то, что показывается человеку.
//
// Ключи узлов сюда не попадают: проверять подписи — дело ядра, а на экране от строки в
// шестьдесят четыре знака никакого проку.
func networkOf(snap control.Snapshot) Network {
	out := Network{Name: snap.Network}
	// В снапшоте только входные узлы: выходных клиенту не показывают вовсе (control.Snapshot).
	for _, n := range snap.Nodes {
		out.Nodes = append(out.Nodes, NodeView{
			ID:        n.ID,
			Domain:    n.Domain,
			Endpoints: n.Endpoints,
		})
	}
	out.HasEgress = snap.Egress
	out.Limit = SettingsView{
		BrutalUpMbps:   snap.Settings.BrutalUpMbps,
		BrutalDownMbps: snap.Settings.BrutalDownMbps,
	}
	return out
}

// usageOf переводит расход из языка управляющего канала в язык состояния.
//
// Перевод, а не общий тип, ради телефона: состояние уедет в приложение, и тянуть за ним
// пакет управляющего канала со всеми его кадрами незачем.
func usageOf(u *control.Usage) *snapshotUsage {
	if u == nil {
		return nil
	}
	return &snapshotUsage{
		Sent:        u.Sent,
		Received:    u.Received,
		LimitBytes:  u.LimitBytes,
		Period:      u.Period,
		Devices:     u.Devices,
		DeviceLimit: u.DeviceLimit,
	}
}

// reportUsage показывает человеку, сколько он потратил.
//
// Кричать об этом на каждый снапшот незачем: цифры растут постоянно, и в журнале от них был
// бы один шум. Предупреждение появляется, только когда лимит близко.
func reportUsage(u *control.Usage, log *slog.Logger) {
	if u == nil {
		return
	}

	spent := u.Sent + u.Received
	fields := []any{"отдано_мб", spent >> 20}
	if u.Period != "" {
		fields = append(fields, "период", u.Period)
	}
	if u.DeviceLimit > 0 {
		fields = append(fields, "устройств", u.Devices, "из", u.DeviceLimit)
	}

	if u.LimitBytes <= 0 {
		log.Debug("расход", fields...)
		return
	}

	left := u.LimitBytes - int64(spent)
	fields = append(fields, "лимит_мб", u.LimitBytes>>20, "осталось_мб", max(left, 0)>>20)
	switch {
	case left <= 0:
		log.Warn("лимит трафика исчерпан: узел откажет при следующем подключении", fields...)
	case spent*10 >= uint64(u.LimitBytes)*9:
		log.Warn("лимит трафика на исходе", fields...)
	default:
		log.Debug("расход", fields...)
	}
}
