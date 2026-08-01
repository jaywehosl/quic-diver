package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Снапшот сети для клиента (решение 005).
//
// Клиенту отдаётся не журнал, а выжимка из него: правила, параметры сети и входные узлы.
// Журнал целиком нёс бы записи обо всех клиентах сети — раздавать список пользователей
// каждому пользователю ради правил маршрутизации незачем.
//
// # Почему выходные узлы сюда не попадают
//
// ТЗ описывает бандл как «все доступные входные узлы + метка о том, что в сети есть и
// выходные». Метка, а не список: клиенту выходные узлы не нужны ни для чего. Он отдаёт
// поток входному, а тот сам объявляет гонку среди выходных — адреса, имена и ключи выхода
// в этой цепочке нигде клиенту не требуются.
//
// Снапшот обязан держать ту же границу, что и бандл. Иначе получается, что через дверь
// инфраструктуру не показывают, а через окно — показывают, и любой клиент сети знает, где
// стоят выходные узлы.

// SnapshotNode — входной узел, каким его видит клиент.
//
// Роли здесь нет намеренно: в этом списке все узлы входные, и поле сообщало бы клиенту
// только о существовании других ролей.
type SnapshotNode struct {
	ID        string          `json:"id"`
	Domain    string          `json:"domain"`
	Endpoints []string        `json:"endpoints"`
	PublicKey oplog.PublicKey `json:"public_key"`
}

// Usage — расход самого клиента, чтобы человек видел, сколько у него осталось.
//
// Только свой: чужие цифры клиенту не нужны и не показываются, как и чужие записи журнала.
type Usage struct {
	Sent     uint64 `json:"sent"`
	Received uint64 `json:"received"`
	// LimitBytes — потолок за период. Ноль означает, что потолка нет.
	LimitBytes int64 `json:"limit_bytes,omitempty"`
	// Period — какой период считается: "daily", "weekly", "monthly" или пусто.
	Period string `json:"period,omitempty"`
	// Devices и DeviceLimit — сколько устройств работает и сколько можно.
	Devices     int `json:"devices,omitempty"`
	DeviceLimit int `json:"device_limit,omitempty"`
}

// Snapshot — что клиент знает о сети.
type Snapshot struct {
	// Network и Genesis — чья это сеть. Клиент сверяет их с бандлом: снапшот из чужой сети
	// применять нельзя, даже если он пришёл по опознанному каналу.
	Network string            `json:"network"`
	Genesis oplog.Fingerprint `json:"genesis"`

	// Правил здесь нет намеренно.
	//
	// ТЗ: «поддержка формата v2fly/loyalsoldier на клиенте. Выбрал geosite:… — отправил в
	// blackhole». Выбирает человек за клиентом, и список правил — его. Сеть их не назначает:
	// применяет-то правила всё равно клиент, и «обязательное» правило от сети было бы
	// обязательным ровно до первой пересборки клиента.
	//
	// Раньше правила ехали здесь и затирали клиентские. Это и было ошибкой (решение 005,
	// пересмотр от 2026-07-31).
	Settings oplog.Settings `json:"settings"`
	// Nodes — только входные узлы. Выходных здесь нет и не будет, см. заголовок пакета.
	Nodes []SnapshotNode `json:"nodes"`
	// Egress — есть ли в сети выходные узлы. Ровно та метка, что и в бандле: без неё
	// чекбоксу «через выходные» нечего предлагать, а с ней клиенту больше ничего не нужно.
	Egress bool `json:"egress"`
	// Usage — расход самого клиента. Пустой, когда узел ничего не считает.
	Usage *Usage `json:"usage,omitempty"`
}

// SnapshotOf собирает снапшот по состоянию журнала.
func SnapshotOf(st *oplog.State) Snapshot {
	s := Snapshot{
		Network:  st.Network(),
		Genesis:  st.Genesis(),
		Settings: st.Settings(),
		Egress:   len(st.NodesWithRole(oplog.RoleEgress)) > 0,
	}
	for _, n := range st.NodesWithRole(oplog.RoleIngress) {
		s.Nodes = append(s.Nodes, SnapshotNode{
			ID:        n.ID,
			Domain:    n.Domain,
			Endpoints: n.Endpoints,
			PublicKey: n.PublicKey,
		})
	}
	return s
}

// Ingress отдаёт входные узлы — те, к кому клиент вправе стучаться.
//
// Отбора здесь больше нет: в снапшоте и так только они. Метод оставлен, потому что имя
// говорит о содержимом точнее, чем Nodes, и не даёт вернуться к мысли, что там кто-то ещё.
func (s Snapshot) Ingress() []SnapshotNode { return s.Nodes }

// HasEgress говорит, есть ли в сети выходные узлы.
func (s Snapshot) HasEgress() bool { return s.Egress }

// WriteSnapshot отправляет снапшот.
func WriteSnapshot(w io.Writer, s Snapshot) error {
	body, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("control: сборка снапшота: %w", err)
	}
	return WriteFrame(w, KindSnapshot, body)
}

// ReadSnapshot разбирает тело кадра снапшота.
func ReadSnapshot(payload []byte) (Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(payload, &s); err != nil {
		return s, fmt.Errorf("control: разбор снапшота: %w", err)
	}
	return s, nil
}

// UsageOf сообщает расход клиента. Пустой означает, что узел ничего не считает.
type UsageOf func(client string) *Usage

// LogSource — источник состояния сети: журнал узла.
//
// Интерфейс, а не `*store.Store`, ради клиента: он снапшоты только читает, а через store
// тянул бы за собой SQLite. На телефоне это лишние мегабайты в установочном пакете за код,
// который там никогда не выполнится.
type LogSource interface {
	// State — текущее состояние сети.
	State() *oplog.State
	// Changed закрывается на следующем изменении журнала.
	Changed() <-chan struct{}
}

// ServeSnapshots отдаёт снапшот и остаётся на связи, посылая новый на каждое изменение
// журнала.
//
// Опрос по таймеру для того же не годится: правка администратора обязана доехать за секунды,
// а молчащий журнал не должен стоить ничего. Узел и так знает, когда применил запись.
//
// Расход обновляется чаще журнала: цифры растут постоянно, и человек, у которого кончается
// лимит, должен это видеть, а не узнавать по отказу.
func ServeSnapshots(ctx context.Context, w io.Writer, st LogSource, client string, usage UsageOf) error {
	ticker := time.NewTicker(usagePeriod)
	defer ticker.Stop()

	for {
		// Канал берётся ДО снимка состояния. Наоборот было бы окном, в которое изменение
		// проскакивает незамеченным: сняли состояние, журнал изменился, и только потом мы
		// подписались — ждать пришлось бы до следующей правки.
		changed := st.Changed()

		snap := SnapshotOf(st.State())
		if usage != nil {
			snap.Usage = usage(client)
		}
		if err := WriteSnapshot(w, snap); err != nil {
			return err
		}

		select {
		case <-changed:
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// usagePeriod — как часто клиенту обновляют цифру расхода.
const usagePeriod = 30 * time.Second
