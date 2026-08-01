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
	// Working и Spare — ссылки владельца: рабочая и запасная.
	Working string
	Spare   string
	// WorkingKey — приватный ключ рабочего владельца. Приложение держит его у себя, чтобы
	// подписывать записи, не разбирая ссылку каждый раз.
	WorkingKey ed25519.PrivateKey
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

	fingerprint := j.Genesis()

	working, err := ownerBundle(name, fingerprint, "владелец", workPriv, p.Password)
	if err != nil {
		return Result{}, err
	}
	spare, err := ownerBundle(name, fingerprint, "владелец-запасной", sparePriv, p.Password)
	if err != nil {
		return Result{}, err
	}

	return Result{
		Journal:    j,
		Genesis:    fingerprint,
		Working:    working,
		Spare:      spare,
		WorkingKey: workPriv,
	}, nil
}

// ownerBundle собирает ссылку владельца.
//
// Узлов в ней нет: их ещё не существует. Клиент, разобравший такую ссылку, знает сеть и свой
// ключ, но подключаться ему пока некуда — до тех пор, пока первый узел не поднимется и не
// пришлёт снапшот со списком.
func ownerBundle(network string, genesis oplog.Fingerprint, id string, priv ed25519.PrivateKey, password string) (string, error) {
	return bundle.Encode(&bundle.Bundle{
		Version:   bundle.Version,
		Network:   network,
		Genesis:   genesis,
		Owner:     true,
		ClientID:  id,
		ClientKey: priv,
	}, password)
}
