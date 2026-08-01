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
	return writeKey(filepath.Join(dir, ownerKeyFile), dir, key)
}

// saveSpareKey придерживает запасной ключ до выдачи ссылок.
//
// Хранить его на устройстве постоянно незачем — вся его ценность в том, что он лежит там, куда
// не дотянется этот телефон. Но между созданием сети и выдачей ссылок проходит время: человек
// идёт на сервер, запускает скрипт, ждёт сертификат. Держать ключ всё это время только в памяти
// значило бы терять сеть от любого закрытия приложения.
//
// Стирается сразу после того, как ссылка выдана.
func saveSpareKey(dir string, key ed25519.PrivateKey) error {
	return writeKey(filepath.Join(dir, spareKeyFile), dir, key)
}

// loadSpareKey читает придержанный запасной ключ.
func loadSpareKey(dir string) (ed25519.PrivateKey, error) {
	return readKey(filepath.Join(dir, spareKeyFile))
}

// dropSpareKey стирает запасной ключ: ссылка выдана, держать его здесь больше нельзя.
func dropSpareKey(dir string) {
	os.Remove(filepath.Join(dir, spareKeyFile))
}

func writeKey(path, dir string, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("ключ владельца должен быть %d байт, получено %d",
			ed25519.PrivateKeySize, len(key))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("каталог состояния: %w", err)
	}

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
	return readKey(filepath.Join(dir, ownerKeyFile))
}

func readKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
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
