// Package admin — то, чем управляют сетью.
//
// Главная мысль решения 001: администратор это ключ, а не сервер. Здесь живёт хранение этого
// ключа и сборка подписанных операций; отправлять их можно через любой живой узел, и никакой
// из них не является главным.
package admin

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Keyring — ключи администратора на диске.
//
// Пока это файл с правами 0600. Хранилище ОС (DPAPI на Windows, keyring на Linux) придёт
// вместе с приложением админа; формат файла от этого не зависит, потому что здесь лежит
// только ключевой материал, а не состояние.
type Keyring struct {
	path string
	keys map[string]storedKey
}

type storedKey struct {
	Private []byte      `json:"private"`
	Scope   oplog.Scope `json:"scope"`
	Label   string      `json:"label,omitempty"`
}

var ErrNoSuchKey = errors.New("admin: такого ключа нет")

// OpenKeyring читает связку ключей, создавая пустую, если файла ещё нет.
func OpenKeyring(path string) (*Keyring, error) {
	k := &Keyring{path: path, keys: make(map[string]storedKey)}

	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return k, nil
	case err != nil:
		return nil, fmt.Errorf("admin: чтение связки ключей: %w", err)
	}
	if err := json.Unmarshal(raw, &k.keys); err != nil {
		return nil, fmt.Errorf("admin: разбор связки ключей: %w", err)
	}
	if err := checkPerms(path); err != nil {
		return nil, err
	}
	return k, nil
}

// checkPerms не даёт работать со связкой, открытой всем.
//
// Проверка не косметическая: этот файл — единственное, чем сеть управляется, и оставленные
// на нём права 0644 означают, что управление есть у любого пользователя машины.
func checkPerms(path string) error {
	if runtime.GOOS == "windows" {
		// На Windows режим файла ничего не значит, права живут в ACL.
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("admin: %w", err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("admin: связка ключей %s открыта посторонним (права %04o), исправь на 0600", path, mode)
	}
	return nil
}

// Add кладёт в связку новый ключ.
func (k *Keyring) Add(label string, scope oplog.Scope, priv ed25519.PrivateKey) (oplog.KeyID, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return oplog.KeyID{}, errors.New("admin: приватный ключ неверной длины")
	}
	if !scope.Valid() {
		return oplog.KeyID{}, fmt.Errorf("admin: неизвестная область прав %d", uint8(scope))
	}
	id := oplog.KeyIDOf(priv.Public().(ed25519.PublicKey))
	k.keys[id.String()] = storedKey{Private: priv, Scope: scope, Label: label}
	return id, k.save()
}

// Generate создаёт новый ключ и кладёт его в связку.
func (k *Keyring) Generate(label string, scope oplog.Scope) (oplog.KeyID, ed25519.PrivateKey, error) {
	s, err := oplog.GenerateSigner()
	if err != nil {
		return oplog.KeyID{}, nil, err
	}
	id, err := k.Add(label, scope, s.Private())
	return id, s.Private(), err
}

// Signer отдаёт подписанта по идентификатору ключа.
func (k *Keyring) Signer(id oplog.KeyID) (*oplog.MemorySigner, oplog.Scope, error) {
	sk, ok := k.keys[id.String()]
	if !ok {
		return nil, 0, fmt.Errorf("%w: %s", ErrNoSuchKey, id)
	}
	s, err := oplog.NewMemorySigner(sk.Private)
	if err != nil {
		return nil, 0, err
	}
	return s, sk.Scope, nil
}

// Any отдаёт первый ключ с правами не ниже требуемых.
//
// Порядок перебора устойчив: связка отсортирована по идентификатору, поэтому одна и та же
// команда всегда подписывается одним и тем же ключом.
func (k *Keyring) Any(min oplog.Scope) (*oplog.MemorySigner, oplog.KeyID, error) {
	for _, id := range k.List() {
		sk := k.keys[id.String()]
		if sk.Scope >= min {
			s, err := oplog.NewMemorySigner(sk.Private)
			return s, id, err
		}
	}
	return nil, oplog.KeyID{}, fmt.Errorf("%w: с правами не ниже %s", ErrNoSuchKey, min)
}

// List перечисляет идентификаторы ключей по возрастанию.
func (k *Keyring) List() []oplog.KeyID {
	ids := make([]oplog.KeyID, 0, len(k.keys))
	for s := range k.keys {
		id, err := oplog.ParseKeyID(s)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	sortKeyIDs(ids)
	return ids
}

// Describe возвращает подпись и права ключа.
func (k *Keyring) Describe(id oplog.KeyID) (label string, scope oplog.Scope, ok bool) {
	sk, ok := k.keys[id.String()]
	return sk.Label, sk.Scope, ok
}

func (k *Keyring) save() error {
	if dir := filepath.Dir(k.path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("admin: создание каталога связки: %w", err)
		}
	}
	raw, err := json.MarshalIndent(k.keys, "", "  ")
	if err != nil {
		return fmt.Errorf("admin: кодирование связки: %w", err)
	}
	if err := os.WriteFile(k.path, raw, 0o600); err != nil {
		return fmt.Errorf("admin: запись связки: %w", err)
	}
	return nil
}

func sortKeyIDs(ids []oplog.KeyID) {
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && less(ids[j], ids[j-1]); j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
}

func less(a, b oplog.KeyID) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
