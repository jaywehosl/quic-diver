package admin

import (
	"fmt"
	"time"

	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/store"
)

// Session — админ со своей копией журнала.
//
// Копия нужна не для скорости: счётчик операций ключа берётся из состояния, а состояние
// собирается из журнала. Админ, не знающий, где он остановился, выдал бы запись с уже
// использованным номером — узлы отвергли бы её как повтор.
type Session struct {
	Store  *store.Store
	Keys   *Keyring
	signer *oplog.MemorySigner
	keyID  oplog.KeyID
	scope  oplog.Scope
}

// NewSession открывает журнал админа и выбирает ключ с нужными правами.
func NewSession(st *store.Store, keys *Keyring, min oplog.Scope) (*Session, error) {
	signer, id, err := keys.Any(min)
	if err != nil {
		return nil, err
	}
	_, scope, _ := keys.Describe(id)
	return &Session{Store: st, Keys: keys, signer: signer, keyID: id, scope: scope}, nil
}

// UseKey переключает сессию на конкретный ключ.
func (s *Session) UseKey(id oplog.KeyID) error {
	signer, scope, err := s.Keys.Signer(id)
	if err != nil {
		return err
	}
	s.signer, s.keyID, s.scope = signer, id, scope
	return nil
}

// KeyID — каким ключом подписываются операции сессии.
func (s *Session) KeyID() oplog.KeyID { return s.keyID }

// Scope — права ключа сессии.
func (s *Session) Scope() oplog.Scope { return s.scope }

// Submit собирает операцию, подписывает её и применяет к своему журналу.
//
// Проверка прав повторяется здесь не из недоверия к узлам, а чтобы человек узнал об отказе
// сразу, а не после того, как разослал по сети запись, которую все отвергнут.
func (s *Session) Submit(kind oplog.Kind, payload any) (*oplog.Op, error) {
	if s.scope < kind.RequiredScope() {
		return nil, fmt.Errorf("admin: для %s нужны права %s, у ключа %s",
			kind, kind.RequiredScope(), s.scope)
	}
	counter := s.Store.State().Counter(s.keyID) + 1
	op, err := oplog.NewOp(s.signer, kind, counter, time.Now().UTC(), payload)
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.Append(op); err != nil {
		return nil, err
	}
	return op, nil
}

// InitNetwork создаёт сеть: генезис с двумя владельцами.
//
// Второй ключ обязателен по решению 001 и хранится офлайн. Потеря единственного ключа
// означала бы, что сеть работает, а управлять ею больше нельзя никогда.
func InitNetwork(st *store.Store, keys *Keyring, network string) (oplog.Fingerprint, error) {
	if !st.State().Genesis().IsZero() {
		return oplog.Fingerprint{}, fmt.Errorf("admin: сеть %q уже создана", st.State().Network())
	}

	const (
		mainLabel  = "основной"
		spareLabel = "запасной, держать офлайн"
	)

	_, mainPriv, err := keys.Generate(mainLabel, oplog.ScopeOwner)
	if err != nil {
		return oplog.Fingerprint{}, err
	}
	_, sparePriv, err := keys.Generate(spareLabel, oplog.ScopeOwner)
	if err != nil {
		return oplog.Fingerprint{}, err
	}

	signer, err := oplog.NewMemorySigner(mainPriv)
	if err != nil {
		return oplog.Fingerprint{}, err
	}
	spare, err := oplog.NewMemorySigner(sparePriv)
	if err != nil {
		return oplog.Fingerprint{}, err
	}

	genesis := oplog.Genesis{
		Network: network,
		Owners: []oplog.AdminKey{
			{PublicKey: oplog.PublicKey(signer.Public()), Scope: oplog.ScopeOwner, Label: mainLabel},
			{PublicKey: oplog.PublicKey(spare.Public()), Scope: oplog.ScopeOwner, Label: spareLabel},
		},
	}
	op, err := oplog.NewOp(signer, oplog.KindGenesis, 1, time.Now().UTC(), genesis)
	if err != nil {
		return oplog.Fingerprint{}, err
	}
	if _, err := st.Append(op); err != nil {
		return oplog.Fingerprint{}, err
	}
	return st.State().Genesis(), nil
}
