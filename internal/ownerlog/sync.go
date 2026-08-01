package ownerlog

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jaywehosl/quic-diver/internal/control"
	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/node"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Разнос правок по сети (решение 007 §1).
//
// # Почему это не «отправить запись узлу»
//
// Записи не отправляются, а сверяются. Владелец говорит узлу, где он находится — последний
// счётчик каждого ключа, — узел отвечает тем же, и каждый досылает недостающее. Тот же обмен,
// каким сверяются узлы между собой.
//
// Разница существенная. Отправка требует знать, что у собеседника уже есть, — а этого никто не
// знает: узлы разносят записи друг другу сами, и к моменту нашего прихода правка могла добраться
// до них соседним путём. Сверка это учитывает по построению, а заодно приносит чужие записи:
// сеть правят и с других устройств, запасной ссылкой.
//
// # Достаточно одного узла
//
// Дальше запись расходится сама: узлы сверяются между собой постоянно (решение 001). Обходить
// всех подряд незачем — но и вредного в этом нет, поэтому обходятся все известные, пока не
// выйдет хотя бы с одним. Узел в отключке не должен останавливать работу.

// syncTimeout ограничивает обмен с одним узлом.
//
// Журнал владельца мал, и обмен занимает миллисекунды. Секунды здесь — на дорогу, а не на
// работу: узел может быть далеко, а сотовая сеть медленной.
const syncTimeout = 20 * time.Second

// ErrNoReachableNode означает, что ни один узел сети не отозвался.
var ErrNoReachableNode = errors.New("ownerlog: ни один узел не ответил")

// PushResult — что дал разнос.
type PushResult struct {
	// Node — узел, с которым вышло. Пустой означает, что не вышло ни с кем.
	Node string
	// Sent и Received — сколько записей отдали и приняли.
	Sent, Received int
	// Failed — узлы, с которыми не вышло, и почему.
	Failed map[string]string
}

// Fetch наполняет пустой журнал из сети.
//
// Так владелец возвращает управление на чистом устройстве: ссылка даёт ключ и адреса узлов, а
// журнал приезжает от любого из них — сверкой, как обычно. Своих записей у нас нет, поэтому
// обмен выходит односторонним, но кода это не меняет.
//
// Отпечаток обязателен: ключи владельцев объявляет сам генезис, и проверить его подписью
// нечем. Единственное, что отличает свою сеть от чужой, — число из ссылки (см. Expect).
func (j *Journal) Fetch(
	ctx context.Context,
	fingerprint oplog.Fingerprint,
	nodes []oplog.Node,
	ownerKey ed25519.PrivateKey,
	log *slog.Logger,
) (PushResult, error) {
	if fingerprint.IsZero() {
		return PushResult{}, errors.New("ownerlog: не задан отпечаток сети")
	}
	if len(nodes) == 0 {
		return PushResult{}, ErrNoReachableNode
	}
	j.Expect(fingerprint)
	return j.exchange(ctx, nodes, ownerKey, log)
}

// Push разносит правки по сети и забирает чужие.
//
// Обходит известные узлы, пока не выйдет хотя бы с одним: дальше запись расходится сама. Узел,
// который сейчас в отключке, получит её от соседей — ждать его незачем.
func (j *Journal) Push(ctx context.Context, ownerKey ed25519.PrivateKey, log *slog.Logger) (PushResult, error) {
	if j.Genesis().IsZero() {
		return PushResult{}, ErrNoGenesis
	}
	return j.exchange(ctx, j.State().NodesWithRole(oplog.RoleIngress), ownerKey, log)
}

// exchange сверяется с узлами, пока не выйдет хотя бы с одним.
func (j *Journal) exchange(
	ctx context.Context,
	nodes []oplog.Node,
	ownerKey ed25519.PrivateKey,
	log *slog.Logger,
) (PushResult, error) {
	if len(ownerKey) != ed25519.PrivateKeySize {
		return PushResult{}, errors.New("ownerlog: не задан ключ владельца")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	signer, err := oplog.NewMemorySigner(ownerKey)
	if err != nil {
		return PushResult{}, err
	}
	self := hello.Identity{
		// Владелец представляется админским ключом: узел ищет его среди ключей из генезиса, а
		// не в списке клиентов, где его нет и не будет.
		Role:   hello.RoleAdmin,
		ID:     signer.KeyID().String(),
		Signer: signer,
	}

	if len(nodes) == 0 {
		return PushResult{}, ErrNoReachableNode
	}

	out := PushResult{Failed: make(map[string]string)}
	for _, n := range nodes {
		res, err := j.syncWith(ctx, n, self, log)
		if err != nil {
			out.Failed[n.ID] = err.Error()
			log.Debug("узел не ответил", "node", n.ID, "err", err)
			continue
		}
		out.Node, out.Sent, out.Received = n.ID, res.Sent, res.Received
		log.Info("журнал сверен с узлом", "node", n.ID, "отдано", res.Sent, "принято", res.Received)
		return out, nil
	}
	return out, ErrNoReachableNode
}

// syncWith сверяется с одним узлом.
func (j *Journal) syncWith(
	ctx context.Context,
	n oplog.Node,
	self hello.Identity,
	log *slog.Logger,
) (control.SyncResult, error) {
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()

	// Гонка по адресам узла: у него бывает и v4, и v6, а рабочим оказывается не всегда первый —
	// у телефона может не быть маршрута до IPv6 вовсе.
	conn, err := node.DialRace(ctx, []node.Target{{
		ID:        n.ID,
		Domain:    n.Domain,
		Endpoints: n.Endpoints,
		PublicKey: n.PublicKey,
	}}, &tls.Config{}, self, 0, log)
	if err != nil {
		return control.SyncResult{}, err
	}
	defer conn.Close()

	res, err := control.Sync(conn.Stream(), j)
	if err != nil {
		return res, fmt.Errorf("сверка с %s: %w", n.ID, err)
	}
	return res, nil
}
