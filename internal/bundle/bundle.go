// Package bundle — то, что человек получает от администратора и вставляет в клиент.
//
// Внутри всё, что нужно для первого подключения: чья это сеть, кто клиент, куда стучаться и
// каким ключом доказывать, что он свой. Решение 004 описывает форму и границы.
package bundle

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/scrypt"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Scheme — схема URI бандла.
const Scheme = "qdiver://"

// Version — версия формата. Меняется, когда старый клиент перестал бы понимать новый бандл.
const Version = 1

// Признак того, зашифровано ли тело. Первым байтом, чтобы не гадать по длине и не пробовать
// расшифровать «на всякий случай»: молчаливая догадка здесь обернулась бы невнятной ошибкой.
const (
	plainBody     = 0x00
	encryptedBody = 0x01
)

// maxBody ограничивает разбираемое тело: бандл приходит от человека, а человек мог вставить
// что угодно.
const maxBody = 1 << 20

// Ошибки разбора.
var (
	ErrNotBundle       = errors.New("bundle: это не ссылка вида qdiver://…")
	ErrNeedPassword    = errors.New("bundle: бандл зашифрован, нужен пароль")
	ErrUnexpectedPass  = errors.New("bundle: бандл не зашифрован, пароль не нужен")
	ErrWrongPassword   = errors.New("bundle: пароль не подходит")
	ErrUnknownVersion  = errors.New("bundle: незнакомая версия бандла")
	ErrNoIngress       = errors.New("bundle: в бандле нет ни одного входного узла")
	ErrBrokenStructure = errors.New("bundle: бандл не разбирается")
)

// Node — входной узел, каким его видит клиент.
type Node struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	// Endpoints — адреса вида host:port, литералами.
	//
	// Именем не обойтись: исключения маршрутизации ставятся до включения туннеля, а внутри
	// него имя узла разрешать уже нечем.
	Endpoints []string        `json:"endpoints"`
	PublicKey oplog.PublicKey `json:"public_key"`
}

// Bundle — всё, что нужно клиенту для первого подключения.
type Bundle struct {
	Version int `json:"version"`
	// Network — имя сети, для человека.
	Network string `json:"network"`
	// Genesis — отпечаток генезиса: им клиент отличает свою сеть от чужой.
	Genesis oplog.Fingerprint `json:"genesis"`

	// Owner отмечает ссылку владельца: в ней лежит ключ из генезиса, а не ключ клиента.
	//
	// Поле — подсказка своему же приложению, чтобы оно знало, показывать ли управление. Правом
	// оно не является и защитой не работает: узел смотрит на подпись и на область ключа в
	// журнале, а что написано в ссылке, его не касается вовсе (решение 007 §1.1).
	Owner bool `json:"owner,omitempty"`

	// ClientID и ClientKey — кто клиент и чем он это докажет.
	ClientID  string `json:"client_id"`
	ClientKey []byte `json:"client_key"`

	// Ingress — входные узлы. Клиент обращается ко всем сразу.
	Ingress []Node `json:"ingress"`
	// HasEgress — есть ли в сети выходные узлы. Без них чекбокс «через выходные» бессмыслен.
	HasEgress bool `json:"has_egress"`

	// Settings — параметры сети на момент выпуска.
	Settings oplog.Settings `json:"settings,omitempty"`
}

// Validate проверяет бандл на пригодность.
func (b *Bundle) Validate() error {
	if b.Version != Version {
		return fmt.Errorf("%w: %d, а понимаем %d", ErrUnknownVersion, b.Version, Version)
	}
	if b.ClientID == "" {
		return fmt.Errorf("%w: нет имени клиента", ErrBrokenStructure)
	}
	if len(b.ClientKey) == 0 {
		return fmt.Errorf("%w: нет ключа клиента", ErrBrokenStructure)
	}
	// Ссылка владельца рождается раньше первого узла: сеть создаётся на устройстве, офлайн, и
	// узлов в этот момент нет ни одного (решение 007 §2). Пустой список для неё — обычное
	// состояние, а не поломка; узлы приедут снапшотом, как только первый из них поднимется.
	if len(b.Ingress) == 0 && !b.Owner {
		return ErrNoIngress
	}
	for i, n := range b.Ingress {
		if n.Domain == "" {
			return fmt.Errorf("%w: узел %d без домена", ErrBrokenStructure, i)
		}
		if len(n.Endpoints) == 0 {
			return fmt.Errorf("%w: у узла %s нет адресов", ErrBrokenStructure, n.ID)
		}
		if len(n.PublicKey) == 0 {
			return fmt.Errorf("%w: у узла %s нет ключа", ErrBrokenStructure, n.ID)
		}
	}
	return nil
}

// Encode собирает ссылку. Пустой пароль означает, что тело едет открытым.
func Encode(b *Bundle, password string) (string, error) {
	if err := b.Validate(); err != nil {
		return "", err
	}

	raw, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("bundle: сборка: %w", err)
	}

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return "", fmt.Errorf("bundle: сжатие: %w", err)
	}
	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("bundle: сжатие: %w", err)
	}

	body := buf.Bytes()
	if password == "" {
		body = append([]byte{plainBody}, body...)
	} else {
		sealed, err := seal(body, password)
		if err != nil {
			return "", err
		}
		body = append([]byte{encryptedBody}, sealed...)
	}
	return Scheme + base64.RawURLEncoding.EncodeToString(body), nil
}

// Decode разбирает ссылку.
//
// Пароль спрашивается отдельной ошибкой, а не молчаливой неудачей: человек должен понять,
// что бандл цел, а не подумать, будто ему дали мусор.
func Decode(uri, password string) (*Bundle, error) {
	uri = strings.TrimSpace(uri)
	if !strings.HasPrefix(uri, Scheme) {
		return nil, ErrNotBundle
	}

	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(uri, Scheme))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotBundle, err)
	}
	if len(body) < 2 {
		return nil, ErrBrokenStructure
	}

	kind, payload := body[0], body[1:]
	switch kind {
	case plainBody:
		if password != "" {
			return nil, ErrUnexpectedPass
		}
	case encryptedBody:
		if password == "" {
			return nil, ErrNeedPassword
		}
		if payload, err = open(payload, password); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: неизвестный вид тела %#x", ErrBrokenStructure, kind)
	}

	zr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBrokenStructure, err)
	}
	defer zr.Close()

	raw, err := io.ReadAll(io.LimitReader(zr, maxBody))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBrokenStructure, err)
	}

	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBrokenStructure, err)
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

// Параметры вывода ключа из пароля.
//
// Пароль здесь — единственное, что стоит между перехваченной ссылкой и приватным ключом
// клиента, поэтому перебор должен быть дорогим. Числа — те, что рекомендует автор scrypt для
// интерактивного случая: около ста миллисекунд и 64 МиБ на одну попытку.
const (
	scryptN    = 1 << 16
	scryptR    = 8
	scryptP    = 1
	saltSize   = 16
	keySize    = 32
	nonceSize  = 12
	minSealed  = saltSize + nonceSize + 16
	sealedInfo = "qdiver-bundle-v1"
)

func deriveKey(password string, salt []byte) ([]byte, error) {
	key, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, keySize)
	if err != nil {
		return nil, fmt.Errorf("bundle: вывод ключа: %w", err)
	}
	return key, nil
}

func seal(payload []byte, password string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("bundle: соль: %w", err)
	}
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("bundle: одноразовое число: %w", err)
	}

	out := make([]byte, 0, minSealed+len(payload))
	out = append(out, salt...)
	out = append(out, nonce...)
	// Метка версии попадает под подпись AEAD: бандл, выданный под другой формат, не должен
	// молча расшифроваться в мусор.
	return gcm.Seal(out, nonce, payload, []byte(sealedInfo)), nil
}

func open(sealed []byte, password string) ([]byte, error) {
	if len(sealed) < minSealed {
		return nil, ErrBrokenStructure
	}
	salt, nonce, body := sealed[:saltSize], sealed[saltSize:saltSize+nonceSize], sealed[saltSize+nonceSize:]

	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	out, err := gcm.Open(nil, nonce, body, []byte(sealedInfo))
	if err != nil {
		// Отличить неверный пароль от испорченной ссылки нечем и не нужно: и то и другое
		// человек чинит одинаково — просит бандл заново.
		return nil, ErrWrongPassword
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("bundle: шифр: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("bundle: режим: %w", err)
	}
	return gcm, nil
}
