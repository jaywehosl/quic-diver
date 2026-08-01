package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/jaywehosl/quic-diver/internal/client"
	qdcontrol "github.com/jaywehosl/quic-diver/internal/control"
	"github.com/jaywehosl/quic-diver/internal/ownerlog"
)

// Управление сетью со стороны приложения (решение 007 §1).
//
// # Каждая правка — запись в журнал, а не команда узлу
//
// Методы здесь ничего не приказывают серверам: они дописывают запись в журнал владельца и
// разносят его сверкой с любым живым узлом. Дальше запись расходится по сети сама — узлы
// сверяются между собой постоянно.
//
// Отсюда важное для интерфейса: правка удалась ещё до того, как о ней узнала сеть. Узел в
// отключке получит её позже, от соседей, и ждать его незачем. Поэтому «не удалось разнести» —
// это предупреждение, а не отказ: запись уже в журнале и никуда не денется.

// pushTimeout ограничивает разнос правки по сети.
const pushTimeout = 30 * time.Second

// AddClient заводит клиента и выдаёт ему ссылку.
//
// limitGB — потолок трафика в гигабайтах, ноль означает «без потолка». period — "daily",
// "weekly", "monthly" либо пусто. devices — сколько устройств могут работать разом, ноль
// означает «без счёта». days — через сколько дней доступ кончится, ноль означает «бессрочно».
//
// Долгий вызов: пароль превращается в ключ шифрования, потом идёт связь с узлом.
func AddClient(id, label string, limitGB, devices, days int, period, password string) (string, error) {
	j, dir, key, err := ownerSession()
	if err != nil {
		return "", err
	}

	p := ownerlog.ClientParams{
		ID:            id,
		Label:         label,
		TrafficBytes:  int64(limitGB) << 30,
		TrafficPeriod: period,
		Devices:       devices,
	}
	if days > 0 {
		until := time.Now().AddDate(0, 0, days)
		p.ExpiresAt = &until
	}

	uri, err := j.AddClient(key, p, password)
	if err != nil {
		return "", err
	}
	return uri, finish(j, dir, key)
}

// UpdateClient меняет лимиты и срок уже заведённого клиента.
func UpdateClient(id, label string, limitGB, devices, days int, period string) error {
	j, dir, key, err := ownerSession()
	if err != nil {
		return err
	}

	p := ownerlog.ClientParams{
		ID:            id,
		Label:         label,
		TrafficBytes:  int64(limitGB) << 30,
		TrafficPeriod: period,
		Devices:       devices,
	}
	if days > 0 {
		until := time.Now().AddDate(0, 0, days)
		p.ExpiresAt = &until
	}

	if err := j.UpdateClient(key, p); err != nil {
		return err
	}
	return finish(j, dir, key)
}

// SuspendClient приостанавливает клиента или возвращает его.
//
// Обратимо, в отличие от отзыва: ключ жив, история цела, вернуть человека можно тем же
// движением.
func SuspendClient(id string, on bool) error {
	j, dir, key, err := ownerSession()
	if err != nil {
		return err
	}
	if err := j.SuspendClient(key, id, on); err != nil {
		return err
	}
	return finish(j, dir, key)
}

// RevokeClient убирает клиента из сети. Необратимо: ключ мёртв, нужна новая ссылка.
func RevokeClient(id string) error {
	j, dir, key, err := ownerSession()
	if err != nil {
		return err
	}
	if err := j.RevokeClient(key, id); err != nil {
		return err
	}
	return finish(j, dir, key)
}

// ReissueClient выдаёт клиенту новый ключ и новую ссылку.
//
// Нужно, когда ссылка утекла: старая перестаёт работать, как только запись доходит до узлов.
// Лимиты и срок сохраняются.
func ReissueClient(id, password string) (string, error) {
	j, dir, key, err := ownerSession()
	if err != nil {
		return "", err
	}
	uri, err := j.ReissueClient(key, id, password)
	if err != nil {
		return "", err
	}
	return uri, finish(j, dir, key)
}

// Clients перечисляет клиентов сети.
//
// Отвечает JSON: массив {id, label, suspended, limit_bytes, period, devices, expires_unix}.
func Clients() string {
	j, _, err := ownerJournal()
	if err != nil {
		return "[]"
	}

	type view struct {
		ID          string `json:"id"`
		Label       string `json:"label,omitempty"`
		Suspended   bool   `json:"suspended,omitempty"`
		LimitBytes  int64  `json:"limit_bytes,omitempty"`
		Period      string `json:"period,omitempty"`
		Devices     int    `json:"devices,omitempty"`
		ExpiresUnix int64  `json:"expires_unix,omitempty"`
	}

	out := make([]view, 0, len(j.State().Clients()))
	for _, c := range j.State().Clients() {
		v := view{
			ID:         c.ID,
			Label:      c.Label,
			Suspended:  c.Suspended,
			LimitBytes: c.Limits.TrafficBytes,
			Period:     c.Limits.TrafficPeriod,
			Devices:    c.Limits.Devices,
		}
		if c.ExpiresAt != nil {
			v.ExpiresUnix = c.ExpiresAt.Unix()
		}
		out = append(out, v)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

// Nodes перечисляет узлы сети.
//
// Отвечает JSON: массив {id, domain, roles, endpoints, tags}. Выходные узлы здесь есть — это
// экран владельца, а не клиента: клиенту их не показывают, потому что он их не выбирает.
func Nodes() string {
	j, _, err := ownerJournal()
	if err != nil {
		return "[]"
	}

	type view struct {
		ID        string   `json:"id"`
		Domain    string   `json:"domain"`
		Roles     []string `json:"roles"`
		Endpoints []string `json:"endpoints"`
		Tags      []string `json:"tags,omitempty"`
	}

	nodes := j.State().Nodes()
	out := make([]view, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, view{
			ID:        n.ID,
			Domain:    n.Domain,
			Roles:     n.Roles,
			Endpoints: n.Endpoints,
			Tags:      n.Tags,
		})
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

// UpdateNode меняет роль узла: "ingress", "egress" либо "both".
func UpdateNode(id, role string) error {
	j, dir, key, err := ownerSession()
	if err != nil {
		return err
	}
	roles, err := rolesOf(role)
	if err != nil {
		return err
	}
	if err := j.UpdateNode(key, id, roles, nil); err != nil {
		return err
	}
	return finish(j, dir, key)
}

// RevokeNode убирает узел из сети.
//
// Сам сервер при этом продолжает работать: остановить его отсюда нельзя, и это правильно —
// журнал описывает сеть, а не управляет чужими машинами.
func RevokeNode(id string) error {
	j, dir, key, err := ownerSession()
	if err != nil {
		return err
	}
	if err := j.RevokeNode(key, id); err != nil {
		return err
	}
	return finish(j, dir, key)
}

// NetworkSettings отдаёт параметры сети.
//
// Отвечает JSON: {brutal_up_mbps, brutal_down_mbps, brutal_mesh_mbps, dns_primary,
// dns_secondary, dns_cache_entries, dns_min_ttl, dns_max_ttl}.
func NetworkSettings() string {
	j, _, err := ownerJournal()
	if err != nil {
		return "{}"
	}
	raw, err := json.Marshal(j.State().Settings())
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// SetNetworkSettings меняет параметры сети.
//
// Потолки доезжают до живых соединений, не разрывая их: узел, увидев правку, переставляет число
// в контроллере (см. internal/node/rate.go).
func SetNetworkSettings(up, down, mesh int, dnsPrimary, dnsSecondary string) error {
	j, dir, key, err := ownerSession()
	if err != nil {
		return err
	}

	s := j.State().Settings()
	s.BrutalUpMbps = up
	s.BrutalDownMbps = down
	s.BrutalMeshMbps = mesh
	s.DNSPrimary = dnsPrimary
	s.DNSSecondary = dnsSecondary

	if err := j.SetSettings(key, s); err != nil {
		return err
	}
	return finish(j, dir, key)
}

// FlushDNS просит узлы очистить кеш имён.
//
// Не команда, а состояние: в параметрах ставится метка времени, и узел, увидевший её новее
// применённой, чистит кеш. Так сброс срабатывает и на узлах, которых в момент нажатия не было
// в живых.
func FlushDNS() error {
	j, dir, key, err := ownerSession()
	if err != nil {
		return err
	}
	if err := j.FlushDNS(key); err != nil {
		return err
	}
	return finish(j, dir, key)
}

// SyncNetwork сверяет журнал с сетью, ничего не меняя.
//
// Нужно, чтобы забрать чужие правки: сеть правят и с другого устройства, запасной ссылкой.
func SyncNetwork() error {
	j, dir, key, err := ownerSession()
	if err != nil {
		return err
	}
	return push(j, dir, key)
}

// ownerSession открывает журнал и ключ владельца разом: без ключа править нечем.
func ownerSession() (*ownerlog.Journal, string, []byte, error) {
	j, dir, err := ownerJournal()
	if err != nil {
		return nil, "", nil, err
	}
	key, err := loadOwnerKey(dir)
	if err != nil {
		return nil, "", nil, err
	}
	return j, dir, key, nil
}

// finish закрепляет правку: записывает журнал и разносит его по сети.
//
// Неудача разноса не отменяет правку и потому не ошибка: запись уже в журнале, а узлы получат
// её при следующей сверке — либо от нас, либо от соседей. Возвращается она всё же наверх, чтобы
// приложение могло сказать человеку «сеть пока не в курсе».
func finish(j *ownerlog.Journal, dir string, key []byte) error {
	if err := j.Save(filepath.Join(dir, journalFile)); err != nil {
		return err
	}
	// Клиентская половина берёт узлы отсюда же: список мог поменяться.
	if err := client.RememberNetwork(dir, qdcontrol.SnapshotOf(j.State()), slog.New(newHandler())); err != nil {
		return err
	}
	return push(j, dir, key)
}

// push разносит журнал по сети.
func push(j *ownerlog.Journal, dir string, key []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), pushTimeout)
	defer cancel()

	res, err := j.Push(ctx, key, slog.New(newHandler()))
	if err != nil {
		if errors.Is(err, ownerlog.ErrNoReachableNode) {
			return errors.New("правка записана, но сеть пока о ней не знает: ни один узел не ответил")
		}
		return err
	}
	// Сверка двусторонняя: узел мог прислать чужие записи, и их надо сохранить.
	if res.Received > 0 {
		if err := j.Save(filepath.Join(dir, journalFile)); err != nil {
			return err
		}
		return client.RememberNetwork(dir, qdcontrol.SnapshotOf(j.State()), slog.New(newHandler()))
	}
	return nil
}
