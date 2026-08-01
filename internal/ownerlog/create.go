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

// Создание сети (решение 007 §2).
//
// # Сеть рождается на устройстве, а не на сервере
//
// Генезис — подписанная запись с именем сети и ключами владельцев. Ни одного сервера в этот
// момент не существует, и не должно: узел не может выдать ссылку владельцу, потому что не
// знает ни сети, ни ключей, а если бы знал — тот, кто вскрыл узел, забирал бы сеть себе.
//
// Отсюда снимается очевидное возражение «кнопку „создать сеть“ увидит и нажмёт любой».
// Посторонний создаст свою сеть — с другими ключами и другим отпечатком. К чужим узлам она не
// подойдёт: у них в конфиге чужой отпечаток. Он получит сеть без единого узла, и вреда в этом
// ровно столько же, сколько в новом пустом документе.
//
// # Ключей владельца два
//
// Рабочий и запасной, оба выдаются сразу, под одним паролем. Это и есть механизм
// восстановления: рабочая ссылка живёт в приложении, запасная уносится туда, куда не дотянется
// ни телефон, ни переписка.
//
// Потеряны обе — восстановления нет, и не должно быть. Любой способ «вернуть управление без
// ключа» это второй вход, и он же второй способ управление украсть (решение 007 §2.2).

// Params — что человек вводит на первом экране.
type Params struct {
	// Network — имя сети. Показывается человеку и едет в генезис.
	Network string
	// Password — пароль на обе ссылки владельца. Пустой означает, что ссылки открытые.
	//
	// Пароль шифрует саму ссылку и защищает её при передаче. В сети он не участвует вовсе:
	// узел проверяет подпись и про пароль не знает ничего (решение 007 §1.2).
	Password string
	// Settings — параметры сети: потолки BRUTAL, резолверы, кеш имён.
	Settings oplog.Settings
	// Now подменяет часы в тестах.
	Now func() time.Time
}

// Result — что получилось.
type Result struct {
	// Journal — журнал из одной записи: генезиса.
	Journal *Journal
	// Genesis — отпечаток сети. Он попадёт в конфиг каждого узла.
	Genesis oplog.Fingerprint
	// WorkingKey и SpareKey — приватные ключи владельцев, рабочий и запасной.
	//
	// Ссылки из них собираются потом, в самом конце развёртывания — см. IssueBundles. Здесь
	// их нет намеренно: ссылка, выданная до появления первого узла, не содержит ни одного
	// адреса, и её обладателю некуда идти. Именно так и вышло при первой обкатке — владелец
	// со ссылкой на руках не мог подключиться к собственной сети.
	WorkingKey ed25519.PrivateKey
	SpareKey   ed25519.PrivateKey
}

// Create создаёт сеть.
func Create(p Params) (Result, error) {
	name := strings.TrimSpace(p.Network)
	if name == "" {
		return Result{}, errors.New("ownerlog: не задано имя сети")
	}
	now := p.Now
	if now == nil {
		now = time.Now
	}

	workPub, workPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return Result{}, fmt.Errorf("ownerlog: рабочий ключ: %w", err)
	}
	sparePub, sparePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return Result{}, fmt.Errorf("ownerlog: запасной ключ: %w", err)
	}

	signer, err := oplog.NewMemorySigner(workPriv)
	if err != nil {
		return Result{}, err
	}

	op, err := oplog.NewOp(signer, oplog.KindGenesis, 1, now(), oplog.Genesis{
		Network: name,
		Owners: []oplog.AdminKey{
			{PublicKey: oplog.PublicKey(workPub), Scope: oplog.ScopeOwner, Label: "рабочий"},
			{PublicKey: oplog.PublicKey(sparePub), Scope: oplog.ScopeOwner, Label: "запасной"},
		},
	})
	if err != nil {
		return Result{}, fmt.Errorf("ownerlog: генезис: %w", err)
	}

	j := New()
	if _, err := j.Append(op); err != nil {
		return Result{}, fmt.Errorf("ownerlog: генезис не применился: %w", err)
	}

	// Параметры сети — вторая запись, а не часть генезиса. Генезис задаёт, чья сеть; потолки
	// и резолверы человек меняет потом, и менять их приходится записью в любом случае.
	if p.Settings != (oplog.Settings{}) {
		set, err := oplog.NewOp(signer, oplog.KindSettingsSet, 2, now().Add(time.Millisecond), p.Settings)
		if err != nil {
			return Result{}, fmt.Errorf("ownerlog: параметры сети: %w", err)
		}
		if _, err := j.Append(set); err != nil {
			return Result{}, fmt.Errorf("ownerlog: параметры не применились: %w", err)
		}
	}

	return Result{
		Journal:    j,
		Genesis:    j.Genesis(),
		WorkingKey: workPriv,
		SpareKey:   sparePriv,
	}, nil
}

// IssueBundles выдаёт обе ссылки владельца по состоянию журнала.
//
// # Почему в конце, а не при создании сети
//
// Ссылка — это ключ **и** способ до сети добраться: узлы, их адреса, параметры. При создании
// сети узлов не существует ни одного, и ссылка выходит с пустым списком — ключ есть, идти
// некуда. Ровно это и вышло при первой обкатке: владелец со ссылкой на руках не смог
// подключиться к собственной сети, а после сброса приложения потерял к ней доступ совсем.
//
// Собранная после включения первого узла ссылка несёт и узлы, и потолки — то есть годится и
// для работы, и для восстановления на другом устройстве.
//
// # Что в ней меняется, а что нет
//
// Ключи те же, что созданы в начале: они уже объявлены в генезисе, и заменить их нельзя, не
// переписав сеть. Меняется только список узлов и параметры — то, что к моменту выдачи стало
// известно.
func IssueBundles(j *Journal, working, spare ed25519.PrivateKey, password string) (workingURI, spareURI string, err error) {
	if j == nil || j.Genesis().IsZero() {
		return "", "", ErrNoGenesis
	}
	st := j.State()
	if len(st.NodesWithRole(oplog.RoleIngress)) == 0 {
		return "", "", errors.New("ownerlog: в сети нет ни одного входного узла — ссылку выдавать рано")
	}

	workingURI, err = ownerBundle(j, "владелец", working, password)
	if err != nil {
		return "", "", err
	}
	spareURI, err = ownerBundle(j, "владелец-запасной", spare, password)
	if err != nil {
		return "", "", err
	}
	return workingURI, spareURI, nil
}

// ownerBundle собирает ссылку владельца по журналу.
func ownerBundle(j *Journal, id string, priv ed25519.PrivateKey, password string) (string, error) {
	st := j.State()

	b := &bundle.Bundle{
		Version:   bundle.Version,
		Network:   st.Network(),
		Genesis:   j.Genesis(),
		Owner:     true,
		ClientID:  id,
		ClientKey: priv,
		// Потолки едут вместе с узлами: без них клиент поднимется на обычном Cubic, а человек
		// будет уверен, что работает BRUTAL, который он задавал.
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
