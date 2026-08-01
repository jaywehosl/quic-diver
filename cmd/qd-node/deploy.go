package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jaywehosl/quic-diver/internal/config"
	"github.com/jaywehosl/quic-diver/internal/ownerlog"
	"github.com/jaywehosl/quic-diver/internal/store"
)

// Развёртывание по ключу (решение 007 §3).
//
// # Почему конфиг раскладывает узел, а не скрипт
//
// Ключ развёртывания — это gzip под base64 с контрольной суммой, а внутри JSON. Разобрать такое
// в shell можно только через `base64 -d | gunzip | jq`, то есть завести зависимость от jq и
// написать разбор, который придётся править при каждом изменении формата.
//
// Узел формат и так знает — он им живёт. Скрипт вызывает `qd-node -deploy <ключ>` и получает
// готовый конфиг; ошибка в ключе, опечатка при переносе, ключ от другой версии — всё это
// разбирается кодом, у которого есть тесты, и объясняется человеку по-русски.
//
// # Чего здесь нет
//
// Записей в журнал. Их подписывает владелец своим ключом, а его на сервере нет и быть не
// должно — в этом весь смысл (решение 007 §3.2). Узел создаёт себе пару при первом запуске и
// ждёт, пока владелец впишет его в журнал со своего устройства.

// deployNode раскладывает конфиг узла по ключу развёртывания.
func deployNode(key, configPath string) error {
	d, err := ownerlog.DecodeDeploy(key)
	if err != nil {
		return err
	}

	cfg := config.Defaults()
	cfg.ID = d.ID
	cfg.Domain = d.Domain
	cfg.Genesis = d.Genesis.String()
	cfg.Peers = d.Peers
	// Потолки из ключа — чтобы узел работал с ними от самого старта, а не с прихода журнала.
	// Свежий узел ждёт журнала минутами: человек в это время идёт к телефону вводить код.
	cfg.BrutalDownMbps = d.Settings.BrutalDownMbps
	cfg.BrutalMeshMbps = d.Settings.BrutalMeshMbps

	// Каталоги: конфиг читает root, данные пишет служба.
	if dir := filepath.Dir(configPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("qd-node: каталог настроек: %w", err)
		}
	}

	// Конфиг не перезаписывается вслепую: на нём завязан отпечаток сети, и подмена его при
	// повторном запуске скрипта означала бы, что узел молча переехал в другую сеть.
	if _, err := os.Stat(configPath); err == nil {
		old, err := config.Load(configPath)
		if err == nil && old.Genesis != "" && old.Genesis != cfg.Genesis {
			return fmt.Errorf("qd-node: узел уже настроен на сеть %s, а ключ от %s — "+
				"сначала останови службу и убери %s", old.Genesis, cfg.Genesis, configPath)
		}
	}

	if err := os.WriteFile(configPath, []byte(nodeTOML(cfg)), 0o640); err != nil {
		return fmt.Errorf("qd-node: запись настроек: %w", err)
	}

	fmt.Printf("настройки записаны: %s\nсеть: %s\nотпечаток: %s\nузел: %s (%s), роли: %s\n",
		configPath, d.Network, cfg.Genesis, cfg.ID, cfg.Domain, strings.Join(d.Roles, ", "))
	if len(cfg.Peers) > 0 {
		fmt.Printf("соседи: %s\n", strings.Join(cfg.Peers, ", "))
	} else {
		fmt.Println("соседей нет: журнал придёт от владельца, с его устройства")
	}
	return nil
}

// brutalDown выбирает потолок отправки клиентам.
//
// Журнал главнее файла: там числа правит владелец, и оттуда они расходятся по сети. Но пока
// журнала нет — а свежий узел живёт так минутами, ожидая, когда человек введёт его код в
// приложении, — берётся то, что приехало ключом развёртывания. Иначе всё это время узел работал
// бы на обычном Cubic, хотя потолки заданы.
func brutalDown(cfg config.Node, st *store.Store) int {
	if fromLog := st.State().Settings().BrutalDownMbps; fromLog > 0 {
		return fromLog
	}
	return cfg.BrutalDownMbps
}

// brutalMesh — то же для участка узел↔узел.
func brutalMesh(cfg config.Node, st *store.Store) int {
	if fromLog := st.State().Settings().BrutalMeshMbps; fromLog > 0 {
		return fromLog
	}
	return cfg.BrutalMeshMbps
}

// nodeTOML собирает файл настроек.
//
// Вручную, а не через кодировщик TOML: файл читают и правят люди, и комментарии в нём стоят
// дороже, чем экономия десятка строк здесь. Кодировщик их не пишет.
func nodeTOML(cfg config.Node) string {
	var b strings.Builder
	b.WriteString("# Настройки узла QUIC Diver. Собраны из ключа развёртывания.\n")
	b.WriteString("#\n")
	b.WriteString("# Здесь только то, без чего узел не может начать. Роль, клиенты, лимиты,\n")
	b.WriteString("# параметры службы имён и потолки скорости приходят журналом и меняются на лету.\n\n")

	fmt.Fprintf(&b, "id     = %q\n", cfg.ID)
	fmt.Fprintf(&b, "domain = %q\n\n", cfg.Domain)

	b.WriteString("# :443 — и QUIC, и обычный HTTPS: сайт, живущий только по HTTP/3, встречается\n")
	b.WriteString("# куда реже обычного и уже этим выделяется. :80 нужен ACME и перенаправлению.\n")
	fmt.Fprintf(&b, "listen      = %q\n", cfg.Listen)
	fmt.Fprintf(&b, "listen_tcp  = %q\n", cfg.ListenTCP)
	fmt.Fprintf(&b, "listen_acme = %q\n\n", cfg.ListenACME)

	fmt.Fprintf(&b, "key_file = %q\n", cfg.KeyFile)
	fmt.Fprintf(&b, "data_dir = %q\n\n", cfg.DataDir)

	b.WriteString("# Отпечаток сети. Именно он, а не подпись, отличает наш журнал от чужого:\n")
	b.WriteString("# узел примет только тот журнал, чей генезис даёт это число.\n")
	fmt.Fprintf(&b, "genesis = %q\n\n", cfg.Genesis)

	b.WriteString("# Соседи для первого знакомства. Дальше список узлов приходит журналом.\n")
	if len(cfg.Peers) == 0 {
		b.WriteString("peers = []\n\n")
	} else {
		quoted := make([]string, 0, len(cfg.Peers))
		for _, p := range cfg.Peers {
			quoted = append(quoted, fmt.Sprintf("%q", p))
		}
		fmt.Fprintf(&b, "peers = [%s]\n\n", strings.Join(quoted, ", "))
	}

	fmt.Fprintf(&b, "acme_email = %q\n", cfg.ACMEEmail)
	fmt.Fprintf(&b, "log_level  = %q\n\n", cfg.LogLevel)

	b.WriteString("# Потолки BRUTAL до прихода журнала, Мбит/с. Ноль означает обычный Cubic.\n")
	b.WriteString("# Как только приезжает журнал, верх берут числа из него — там их правит владелец.\n")
	fmt.Fprintf(&b, "brutal_down_mbps = %d\n", cfg.BrutalDownMbps)
	fmt.Fprintf(&b, "brutal_mesh_mbps = %d\n", cfg.BrutalMeshMbps)
	return b.String()
}
