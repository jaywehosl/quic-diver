package ownerlog

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jaywehosl/quic-diver/internal/bundle"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Управление сетью: клиенты, узлы, параметры (решение 007 §1).
//
// # Всё это — подписанные записи
//
// Ни одна операция здесь ничего не «делает» с узлами: она добавляет запись в журнал владельца.
// Дальше журнал сверяется с любым живым узлом (Push), и запись расходится по сети сама.
//
// Отсюда два следствия, которые кажутся неудобством, но являются устройством. Первое: операция
// удалась ещё до того, как о ней узнала сеть, — узел в отключке получит её позже, от соседей.
// Второе: отменить сделанное нельзя, можно только добавить новую запись, — журнал append-only,
// и это единственное, что делает его проверяемым.
//
// # Почему у каждой операции свой метод, а не один Submit(kind, payload)
//
// Собрать запись мало: нужно выбрать счётчик, проверить, что объект существует, придумать ключ
// клиенту, собрать ему ссылку. Общий Submit оставил бы всё это вызывающему — то есть мосту в
// приложение, где ни тестов, ни типов.

// signWith подписывает запись ключом владельца и кладёт её в журнал.
//
// Счётчик берётся из журнала: последовательность ключа идёт без пропусков, и узел, увидевший
// разрыв, отложит запись до недостающей.
func (j *Journal) signWith(key ed25519.PrivateKey, kind oplog.Kind, payload any, now time.Time) (*oplog.Op, error) {
	if j.Genesis().IsZero() {
		return nil, ErrNoGenesis
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("ownerlog: не задан ключ владельца")
	}
	signer, err := oplog.NewMemorySigner(key)
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = j.tick()
	}

	op, err := oplog.NewOp(signer, kind, j.Next(signer.KeyID()), now, payload)
	if err != nil {
		return nil, fmt.Errorf("ownerlog: сборка записи %s: %w", kind, err)
	}
	if _, err := j.Append(op); err != nil {
		return nil, fmt.Errorf("ownerlog: запись %s не применилась: %w", kind, err)
	}
	return op, nil
}

// ClientParams — что задаётся клиенту.
type ClientParams struct {
	// ID — имя клиента в сети. По нему узел ищет его ключ.
	ID string
	// Label — подпись для человека. На работу не влияет.
	Label string
	// TrafficBytes — потолок трафика за период. Ноль означает, что потолка нет.
	TrafficBytes int64
	// TrafficPeriod — "daily", "weekly", "monthly" либо пусто.
	TrafficPeriod string
	// Devices — сколько устройств могут работать разом. Ноль означает, что счёта нет.
	Devices int
	// ExpiresAt — когда доступ кончится. Пустое означает, что не кончится.
	ExpiresAt *time.Time
}

// AddClient заводит клиента и выдаёт ему ссылку.
//
// Ключевая пара рождается здесь и здесь же расстаётся: приватная часть уезжает в ссылку,
// публичная — в журнал. У узлов приватной части нет, и взлом узла не даёт возможности выдать
// себя за клиента.
//
// Ссылка несёт узлы сети и потолки — то же, что и ссылка владельца, но с обычным ключом:
// клиент видит сеть, а управления не видит, потому что показывать ему нечего.
func (j *Journal) AddClient(key ed25519.PrivateKey, p ClientParams, password string) (string, error) {
	id := strings.TrimSpace(p.ID)
	if id == "" {
		return "", errors.New("ownerlog: не задано имя клиента")
	}
	if _, exists := j.State().Client(id); exists {
		return "", fmt.Errorf("ownerlog: клиент %s уже есть", id)
	}
	if len(j.State().NodesWithRole(oplog.RoleIngress)) == 0 {
		// Ссылка без узлов бесполезна — тот же урок, что и с ссылкой владельца.
		return "", errors.New("ownerlog: в сети нет входных узлов — ссылку выдавать рано")
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", fmt.Errorf("ownerlog: ключ клиента: %w", err)
	}

	if _, err := j.signWith(key, oplog.KindClientAdd, oplog.Client{
		ID:        id,
		Label:     strings.TrimSpace(p.Label),
		PublicKey: oplog.PublicKey(pub),
		Limits: oplog.Limits{
			Devices:       p.Devices,
			TrafficBytes:  p.TrafficBytes,
			TrafficPeriod: p.TrafficPeriod,
		},
		ExpiresAt: p.ExpiresAt,
	}, time.Time{}); err != nil {
		return "", err
	}

	return j.clientBundle(id, priv, password)
}

// UpdateClient меняет лимиты и срок.
//
// Записью, а не правкой прежней: журнал append-only, и «изменить» здесь означает «дописать
// новое состояние». Прежняя запись остаётся — по ней видно, что и когда менялось.
func (j *Journal) UpdateClient(key ed25519.PrivateKey, p ClientParams) error {
	c, ok := j.State().Client(strings.TrimSpace(p.ID))
	if !ok {
		return fmt.Errorf("ownerlog: клиента %s нет", p.ID)
	}

	c.Label = strings.TrimSpace(p.Label)
	c.Limits = oplog.Limits{
		Devices:       p.Devices,
		TrafficBytes:  p.TrafficBytes,
		TrafficPeriod: p.TrafficPeriod,
	}
	c.ExpiresAt = p.ExpiresAt

	_, err := j.signWith(key, oplog.KindClientUpdate, c, time.Time{})
	return err
}

// SuspendClient приостанавливает клиента или возвращает его.
//
// Не то же, что отзыв: ключ остаётся живым, история сохраняется, и вернуть человека можно тем
// же движением. Отзыв необратим — там ключ мёртв, и нужна новая ссылка.
func (j *Journal) SuspendClient(key ed25519.PrivateKey, id string, on bool) error {
	c, ok := j.State().Client(strings.TrimSpace(id))
	if !ok {
		return fmt.Errorf("ownerlog: клиента %s нет", id)
	}
	if c.Suspended == on {
		return nil
	}
	c.Suspended = on

	_, err := j.signWith(key, oplog.KindClientUpdate, c, time.Time{})
	return err
}

// RevokeClient убирает клиента из сети.
//
// Необратимо: ключ после этого мёртв, и вернуть человека можно только новой ссылкой. Для
// «на время» есть SuspendClient.
func (j *Journal) RevokeClient(key ed25519.PrivateKey, id string) error {
	id = strings.TrimSpace(id)
	if _, ok := j.State().Client(id); !ok {
		return fmt.Errorf("ownerlog: клиента %s нет", id)
	}
	_, err := j.signWith(key, oplog.KindClientRevoke, oplog.ClientRevoke{ID: id}, time.Time{})
	return err
}

// ReissueClient выдаёт клиенту новый ключ и новую ссылку.
//
// Нужно, когда ссылка утекла: старый ключ перестаёт работать в тот момент, когда запись доходит
// до узлов. Лимиты, срок и подпись сохраняются — меняется только пара.
func (j *Journal) ReissueClient(key ed25519.PrivateKey, id, password string) (string, error) {
	id = strings.TrimSpace(id)
	c, ok := j.State().Client(id)
	if !ok {
		return "", fmt.Errorf("ownerlog: клиента %s нет", id)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", fmt.Errorf("ownerlog: ключ клиента: %w", err)
	}
	c.PublicKey = oplog.PublicKey(pub)

	if _, err := j.signWith(key, oplog.KindClientUpdate, c, time.Time{}); err != nil {
		return "", err
	}
	return j.clientBundle(id, priv, password)
}

// clientBundle собирает ссылку клиента по состоянию журнала.
func (j *Journal) clientBundle(id string, priv ed25519.PrivateKey, password string) (string, error) {
	st := j.State()

	b := &bundle.Bundle{
		Version:   bundle.Version,
		Network:   st.Network(),
		Genesis:   j.Genesis(),
		ClientID:  id,
		ClientKey: priv,
		Settings:  st.Settings(),
		HasEgress: len(st.NodesWithRole(oplog.RoleEgress)) > 0,
	}
	for _, n := range st.NodesWithRole(oplog.RoleIngress) {
		b.Ingress = append(b.Ingress, bundle.Node{
			ID:        n.ID,
			Domain:    n.Domain,
			Endpoints: n.Endpoints,
			PublicKey: n.PublicKey,
		})
	}
	return bundle.Encode(b, password)
}

// UpdateNode меняет роли и подписи узла.
//
// Адреса и ключ не трогаются: их узел назвал сам при включении, и менять их отсюда означало бы
// разойтись с тем, что на самом деле работает на сервере.
func (j *Journal) UpdateNode(key ed25519.PrivateKey, id string, roles, tags []string) error {
	n, ok := j.State().Node(strings.TrimSpace(id))
	if !ok {
		return fmt.Errorf("ownerlog: узла %s нет", id)
	}
	if len(roles) == 0 {
		return errors.New("ownerlog: узел без роли бесполезен")
	}
	n.Roles = roles
	n.Tags = tags

	_, err := j.signWith(key, oplog.KindNodeUpdate, n, time.Time{})
	return err
}

// RevokeNode убирает узел из сети.
//
// Клиенты перестанут к нему ходить, как только запись до них доедет. Сам сервер при этом
// продолжает работать: остановить его отсюда нельзя, и это правильно — журнал описывает сеть, а
// не управляет чужими машинами.
func (j *Journal) RevokeNode(key ed25519.PrivateKey, id string) error {
	id = strings.TrimSpace(id)
	if _, ok := j.State().Node(id); !ok {
		return fmt.Errorf("ownerlog: узла %s нет", id)
	}
	// Последний входной узел — это отрезать всех клиентов разом, включая себя: сверяться с
	// сетью станет не с кем, и вернуть запись обратно будет нечем.
	if left := remaining(j, id, oplog.RoleIngress); left == 0 {
		return errors.New("ownerlog: это последний входной узел — сеть станет недоступна всем, включая тебя")
	}
	_, err := j.signWith(key, oplog.KindNodeRevoke, oplog.NodeRevoke{ID: id}, time.Time{})
	return err
}

// remaining считает, сколько узлов роли останется без указанного.
func remaining(j *Journal, without, role string) int {
	n := 0
	for _, node := range j.State().NodesWithRole(role) {
		if node.ID != without {
			n++
		}
	}
	return n
}

// SetSettings меняет параметры сети.
//
// Потолки доезжают до живых соединений, не разрывая их (см. internal/node/rate.go): узел,
// увидев правку, переставляет число в контроллере. Резолверы и кеш имён узел перечитывает так
// же — по изменению журнала.
func (j *Journal) SetSettings(key ed25519.PrivateKey, s oplog.Settings) error {
	_, err := j.signWith(key, oplog.KindSettingsSet, s, time.Time{})
	return err
}

// FlushDNS просит узлы очистить кеш имён.
//
// Не команда, а состояние: в параметрах ставится метка времени, и узел, увидевший её новее
// применённой, чистит кеш и запоминает. Так сброс расходится по сети сам и срабатывает на
// узлах, которых в момент нажатия не было в живых, — а команда, посланная по сети, до них бы
// не добралась.
func (j *Journal) FlushDNS(key ed25519.PrivateKey) error {
	s := j.State().Settings()
	s.DNSFlushAt = time.Now().Unix()

	_, err := j.signWith(key, oplog.KindSettingsSet, s, time.Time{})
	return err
}
