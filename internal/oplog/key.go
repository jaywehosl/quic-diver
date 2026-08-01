package oplog

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// KeyID — короткий идентификатор ключа: первые 8 байт SHA-256 от публичного ключа.
//
// В записи журнала едет он, а не сам ключ: полные ключи перечислены в генезисе и в записях
// admin.add, так что получателю всегда есть с чем сверить. Восьми байт хватает — подобрать
// второй ключ с тем же идентификатором стоит примерно 2^32 попыток, а подпись всё равно
// проверяется полным ключом, так что коллизия ничего не даёт атакующему.
type KeyID [8]byte

func (k KeyID) String() string { return hex.EncodeToString(k[:]) }

func (k KeyID) IsZero() bool { return k == KeyID{} }

// ParseKeyID разбирает шестнадцатеричную запись идентификатора.
func ParseKeyID(s string) (KeyID, error) {
	var id KeyID
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("oplog: разбор идентификатора ключа: %w", err)
	}
	if len(b) != len(id) {
		return id, fmt.Errorf("oplog: идентификатор ключа должен быть %d байт, получено %d", len(id), len(b))
	}
	copy(id[:], b)
	return id, nil
}

// В JSON идентификатор едет строкой, а не массивом байтов: дамп журнала читают люди,
// и он же уходит в бэкап.
func (k KeyID) MarshalJSON() ([]byte, error) { return json.Marshal(k.String()) }

func (k *KeyID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	id, err := ParseKeyID(s)
	if err != nil {
		return err
	}
	*k = id
	return nil
}

// KeyIDOf вычисляет идентификатор публичного ключа.
func KeyIDOf(pub ed25519.PublicKey) KeyID {
	sum := sha256.Sum256(pub)
	var id KeyID
	copy(id[:], sum[:])
	return id
}

// Scope — что ключу позволено. Порядок значений возрастающий: больше значение — больше прав.
type Scope uint8

const (
	// ScopeViewer только читает: ни одна операция журнала им не подписывается.
	ScopeViewer Scope = 1
	// ScopeOperator ведёт клиентов и их лимиты, но не трогает узлы и не раздаёт права.
	ScopeOperator Scope = 2
	// ScopeOwner может всё, включая выдачу и отзыв ключей.
	ScopeOwner Scope = 3
)

func (s Scope) String() string {
	switch s {
	case ScopeViewer:
		return "viewer"
	case ScopeOperator:
		return "operator"
	case ScopeOwner:
		return "owner"
	default:
		return fmt.Sprintf("scope(%d)", uint8(s))
	}
}

// Valid сообщает, известна ли область прав. Неизвестные значения не считаются полномочиями:
// узел старой версии не должен наделять ключ правами, смысла которых не понимает.
func (s Scope) Valid() bool { return s >= ScopeViewer && s <= ScopeOwner }

// Область прав тоже едет в JSON именем: "owner" в дампе понятнее, чем 3, и опечатка в нём
// поймается разбором, а не превратится молча в другие полномочия.
func (s Scope) MarshalJSON() ([]byte, error) {
	if !s.Valid() {
		return nil, fmt.Errorf("oplog: неизвестная область прав %d", uint8(s))
	}
	return json.Marshal(s.String())
}

func (s *Scope) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	sc, err := ParseScope(str)
	if err != nil {
		return err
	}
	*s = sc
	return nil
}

// ParseScope разбирает имя области прав.
func ParseScope(s string) (Scope, error) {
	switch s {
	case "viewer":
		return ScopeViewer, nil
	case "operator":
		return ScopeOperator, nil
	case "owner":
		return ScopeOwner, nil
	default:
		return 0, fmt.Errorf("oplog: неизвестная область прав %q", s)
	}
}

// Signer подписывает операции. За ним стоит либо файл с ключом, либо хранилище ОС —
// приватный ключ может не покидать его вовсе.
type Signer interface {
	// Public возвращает публичный ключ, которым будет проверяться подпись.
	Public() ed25519.PublicKey
	// Sign подписывает произвольные байты.
	Sign(message []byte) ([]byte, error)
}

// MemorySigner держит приватный ключ в памяти процесса. Годится для узлов и тестов;
// для админского ключа предпочтительнее хранилище ОС.
type MemorySigner struct {
	priv ed25519.PrivateKey
}

// NewMemorySigner оборачивает готовый приватный ключ.
func NewMemorySigner(priv ed25519.PrivateKey) (*MemorySigner, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("oplog: приватный ключ неверной длины")
	}
	return &MemorySigner{priv: priv}, nil
}

// GenerateSigner создаёт новую ключевую пару.
func GenerateSigner() (*MemorySigner, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("oplog: генерация ключа: %w", err)
	}
	return &MemorySigner{priv: priv}, nil
}

func (s *MemorySigner) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

func (s *MemorySigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

// Private отдаёт приватный ключ — нужно для записи его на диск при создании.
func (s *MemorySigner) Private() ed25519.PrivateKey { return s.priv }

// KeyID возвращает идентификатор ключа подписанта.
func (s *MemorySigner) KeyID() KeyID { return KeyIDOf(s.Public()) }
