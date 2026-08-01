// Package config читает файл настроек узла.
//
// В файле лежит только то, без чего узел не может даже начать: свой ключ, где слушать, каким
// именем представляться, отпечаток сети и с кем знакомиться. Всё остальное — роль, категория,
// клиенты, правила, параметры DNS и потолок скорости — приходит журналом и меняется на лету
// (решение 002). Поэтому файл не перечитывается: менять в нём на ходу нечего.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Node — настройки узла.
type Node struct {
	// ID — как узел зовётся в журнале.
	ID string `toml:"id"`
	// Domain — имя, на которое выписан сертификат и по которому к узлу приходят.
	Domain string `toml:"domain"`
	// Listen — адрес QUIC, обычно ":443".
	Listen string `toml:"listen"`
	// ListenTCP — адрес обычного HTTPS для заглушки, обычно ":443".
	ListenTCP string `toml:"listen_tcp"`
	// ListenACME — адрес для проверки владения доменом и редиректа, обычно ":80".
	ListenACME string `toml:"listen_acme"`

	// KeyFile — приватный ключ узла Ed25519.
	KeyFile string `toml:"key_file"`
	// DataDir — где лежат журнал и кеш сертификатов.
	DataDir string `toml:"data_dir"`

	// Genesis — отпечаток сети. Заносится руками при установке: именно он, а не подпись,
	// отличает наш журнал от чужого.
	Genesis string `toml:"genesis"`
	// Peers — адреса соседей для первого знакомства. Дальше список узлов приходит журналом.
	Peers []string `toml:"peers"`

	// ACMEEmail — почта для Let's Encrypt. Пустая допустима.
	ACMEEmail string `toml:"acme_email"`
	// ACMEDirectory — каталог ACME. Пустой означает боевой Let's Encrypt; для проб
	// подставляется staging, чтобы не жечь лимиты.
	ACMEDirectory string `toml:"acme_directory"`

	// LogLevel — debug, info, warn или error.
	LogLevel string `toml:"log_level"`
}

// Defaults возвращает настройки со значениями по умолчанию.
func Defaults() Node {
	return Node{
		Listen:     ":443",
		ListenTCP:  ":443",
		ListenACME: ":80",
		DataDir:    "/var/lib/qdiver",
		KeyFile:    "/var/lib/qdiver/node.key",
		LogLevel:   "info",
	}
}

// Load читает файл настроек.
func Load(path string) (Node, error) {
	cfg := Defaults()
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("config: чтение %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		// Непонятый ключ — это либо опечатка, либо файл от более новой версии. Тихо
		// проигнорировать его значит запустить узел не с теми настройками, о которых
		// думает человек.
		names := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			names = append(names, k.String())
		}
		return cfg, fmt.Errorf("config: непонятные ключи в %s: %s", path, strings.Join(names, ", "))
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Validate проверяет настройки.
func (n Node) Validate() error {
	if strings.TrimSpace(n.ID) == "" {
		return errors.New("config: не задан id узла")
	}
	if strings.TrimSpace(n.Domain) == "" {
		return errors.New("config: не задан domain — без него нет сертификата")
	}
	if n.Listen == "" {
		return errors.New("config: не задан listen")
	}
	if n.DataDir == "" {
		return errors.New("config: не задан data_dir")
	}
	if n.KeyFile == "" {
		return errors.New("config: не задан key_file")
	}
	if n.Genesis != "" {
		if _, err := oplog.ParseFingerprint(n.Genesis); err != nil {
			return fmt.Errorf("config: genesis: %w", err)
		}
	}
	return nil
}

// Fingerprint разбирает отпечаток сети. Пустой отпечаток допустим только у самого первого
// узла, который сеть и создаёт.
func (n Node) Fingerprint() (oplog.Fingerprint, error) {
	if n.Genesis == "" {
		return oplog.Fingerprint{}, nil
	}
	return oplog.ParseFingerprint(n.Genesis)
}

// StorePath — путь к журналу.
func (n Node) StorePath() string { return filepath.Join(n.DataDir, "oplog.db") }

// CertDir — где autocert держит сертификаты.
func (n Node) CertDir() string { return filepath.Join(n.DataDir, "certs") }

// EnsureDirs создаёт каталоги узла.
//
// Права 0700: в каталоге лежат приватный ключ узла и ключи сертификатов.
func (n Node) EnsureDirs() error {
	for _, dir := range []string{n.DataDir, n.CertDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("config: создание %s: %w", dir, err)
		}
	}
	return nil
}
