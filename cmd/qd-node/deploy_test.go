package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaywehosl/quic-diver/internal/config"
	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/ownerlog"
)

func deployKeyFor(t *testing.T, id, domain string, peers []string) (string, oplog.Fingerprint) {
	t.Helper()

	res, err := ownerlog.Create(ownerlog.Params{
		Network:  "qdiver",
		Settings: oplog.Settings{BrutalUpMbps: 100, BrutalDownMbps: 300},
	})
	if err != nil {
		t.Fatalf("сеть: %v", err)
	}

	d := res.Journal.DeployFor(id, domain, []string{"ingress"})
	d.Peers = peers

	key, err := ownerlog.EncodeDeploy(d)
	if err != nil {
		t.Fatalf("ключ развёртывания: %v", err)
	}
	return key, res.Genesis
}

// Ключ разбирает узел, а не скрипт: shell не должен знать ни про gzip, ни про JSON.
func TestDeployWritesConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qdiver", "node.toml")
	key, genesis := deployKeyFor(t, "node7", "seven.example", []string{"203.0.113.1:443"})

	if err := deployNode(key, path); err != nil {
		t.Fatalf("раскладка: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("чтение настроек: %v", err)
	}
	if cfg.ID != "node7" || cfg.Domain != "seven.example" {
		t.Fatalf("узел записан неверно: %+v", cfg)
	}
	if cfg.Genesis != genesis.String() {
		t.Fatalf("отпечаток %s, ожидался %s", cfg.Genesis, genesis)
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0] != "203.0.113.1:443" {
		t.Fatalf("соседи записаны неверно: %v", cfg.Peers)
	}
	// Умолчания должны доехать: скрипт их не задаёт и задавать не должен.
	if cfg.Listen != ":443" || cfg.ListenACME != ":80" || cfg.KeyFile == "" {
		t.Fatalf("умолчания потерялись: %+v", cfg)
	}
}

// Файл читают и правят люди — комментарии в нём стоят дороже экономии кода.
func TestDeployConfigIsReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.toml")
	key, _ := deployKeyFor(t, "node1", "one.example", nil)

	if err := deployNode(key, path); err != nil {
		t.Fatalf("раскладка: %v", err)
	}
	raw := readFile(t, path)

	for _, want := range []string{"# Настройки узла", "genesis =", "peers = []"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("в настройках нет %q:\n%s", want, raw)
		}
	}
}

// Повторный запуск скрипта с ключом от другой сети не должен молча переселять узел: отпечаток
// в конфиге — единственное, чем узел отличает свой журнал от чужого.
func TestDeployRefusesForeignNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.toml")

	first, _ := deployKeyFor(t, "node1", "one.example", nil)
	if err := deployNode(first, path); err != nil {
		t.Fatalf("первая раскладка: %v", err)
	}
	before := readFile(t, path)

	second, _ := deployKeyFor(t, "node1", "one.example", nil)
	err := deployNode(second, path)
	if err == nil {
		t.Fatal("ключ от другой сети принят поверх настроенного узла")
	}
	if !strings.Contains(err.Error(), "уже настроен") {
		t.Fatalf("причина отказа невнятная: %v", err)
	}
	if readFile(t, path) != before {
		t.Fatal("настройки всё-таки переписаны")
	}
}

// Тот же ключ повторно — обычное дело: скрипт перезапустили, потому что он упал на пакетах.
func TestDeployIsRepeatable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.toml")
	key, _ := deployKeyFor(t, "node1", "one.example", nil)

	if err := deployNode(key, path); err != nil {
		t.Fatalf("первая раскладка: %v", err)
	}
	if err := deployNode(key, path); err != nil {
		t.Fatalf("повтор тем же ключом отвергнут: %v", err)
	}
}

// Испорченный при переносе ключ отвергается до всякой записи на диск.
func TestDeployRejectsBrokenKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.toml")

	if err := deployNode("qdnode:abc.00000000", path); err == nil {
		t.Fatal("мусор принят за ключ развёртывания")
	}
	if _, err := config.Load(path); err == nil {
		t.Fatal("настройки записаны, хотя ключ негоден")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение %s: %v", path, err)
	}
	return string(raw)
}
