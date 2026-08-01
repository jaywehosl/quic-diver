package mobile

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Ключ рабочего владельца на устройстве.
//
// Держится файлом рядом с журналом, а не в SharedPreferences: те попадают в резервную копию
// системы, то есть в чужое облако. Приложение объявляет `allowBackup=false`, но ключ от всей
// сети — не то, что стоит доверять одному флагу в манифесте.
//
// Шифровать его паролем здесь незачем: пароль защищает ссылку **при передаче**, а на устройстве
// защита другая — каталог приложения, куда без root не заглянуть. Спрашивать пароль на каждую
// подпись означало бы, что человек начнёт его упрощать.

// saveOwnerKey записывает приватный ключ владельца.
func saveOwnerKey(dir string, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("ключ владельца должен быть %d байт, получено %d",
			ed25519.PrivateKeySize, len(key))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("каталог состояния: %w", err)
	}

	path := filepath.Join(dir, ownerKeyFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		return fmt.Errorf("запись ключа владельца: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("замена ключа владельца: %w", err)
	}
	return nil
}

// loadOwnerKey читает приватный ключ владельца.
func loadOwnerKey(dir string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ownerKeyFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("ключа владельца на этом устройстве нет: вставь ссылку владельца")
		}
		return nil, fmt.Errorf("чтение ключа владельца: %w", err)
	}

	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("ключ владельца испорчен: %w", err)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ключ владельца длиной %d байт вместо %d", len(key), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(key), nil
}
