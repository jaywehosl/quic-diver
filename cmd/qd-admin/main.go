// Команда qd-admin — управление сетью.
//
// Администратор здесь не сервер, а ключ (решение 001): все изменения это подписанные записи
// журнала, и любой живой узел годится, чтобы их разнести. Пока доставка идёт файлом через
// export и import; по сети она поедет тем же управляющим каналом, что уже работает.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jaywehosl/quic-diver/internal/admin"
	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "qd-admin:", err)
		os.Exit(1)
	}
}

const usage = `qd-admin — управление сетью QUIC Diver

  init <имя-сети>            создать сеть: два ключа владельца и генезис
  node add                   добавить узел
  client add                 завести клиента и выдать бандл
  client reissue             выдать клиенту новый ключ и новый бандл
  settings set               задать параметры сети: потолки BRUTAL, резолверы, кеш
  settings show              показать параметры сети
  dns flush                  мягко сбросить кеш имён на всех узлах
  list                       показать состояние сети
  export <файл>              выгрузить журнал (он же бэкап)
  import <файл>              влить журнал
  push <адрес>               залить журнал в свежий узел по сети (только пока он пуст)

Общие флаги:
  -dir <путь>   рабочий каталог админа (по умолчанию ~/.qdiver)
`

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}

	switch args[0] {
	case "init":
		return cmdInit(args[1:])
	case "node":
		if len(args) > 1 && args[1] == "add" {
			return cmdNodeAdd(args[2:])
		}
		return fmt.Errorf("неизвестная команда node %s", strings.Join(args[1:], " "))
	case "client":
		if len(args) > 1 {
			switch args[1] {
			case "add":
				return cmdClientAdd(args[2:])
			case "reissue":
				return cmdClientReissue(args[2:])
			}
		}
		return fmt.Errorf("неизвестная команда client %s", strings.Join(args[1:], " "))
	case "routing":
		// Правила больше не сетевые: их задаёт человек у себя в клиенте (ТЗ ст. 36,
		// пересмотр решения 005). Команда убрана, а не оставлена молчать: администратор,
		// написавший правило в журнал, был бы уверен, что оно работает, — а оно не работает.
		return errors.New("правила маршрутизации задаются в клиенте, а не в сети:\n" +
			"  сеть их не назначает — применяет-то их всё равно клиент.\n" +
			"  Прежние записи в журнале остались, но никем не читаются.")
	case "settings":
		if len(args) > 1 {
			switch args[1] {
			case "set":
				return cmdSettingsSet(args[2:])
			case "show":
				return cmdSettingsShow(args[2:])
			}
		}
		return fmt.Errorf("неизвестная команда settings %s", strings.Join(args[1:], " "))
	case "dns":
		if len(args) > 1 && args[1] == "flush" {
			return cmdDNSFlush(args[2:])
		}
		return fmt.Errorf("неизвестная команда dns %s", strings.Join(args[1:], " "))
	case "list":
		return cmdList(args[1:])
	case "export":
		return cmdExport(args[1:])
	case "import":
		return cmdImport(args[1:])
	case "push":
		return cmdPush(args[1:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("неизвестная команда %q", args[0])
	}
}

// workdir открывает журнал и связку ключей админа.
func workdir(fs *flag.FlagSet, args []string) (*store.Store, *admin.Keyring, error) {
	dir := fs.String("dir", defaultDir(), "рабочий каталог админа")
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	// Разбор флагов обрывается на первом позиционном аргументе, и всё, что за ним, молча
	// пропадает. Для команды, выбирающей каталог с ключами от всей сети, «молча» недопустимо:
	// qd-admin init qdiver -dir /tmp/x создал бы сеть совсем не там, где человек ожидает.
	for _, rest := range fs.Args() {
		if strings.HasPrefix(rest, "-") {
			return nil, nil, fmt.Errorf("флаг %s стоит после позиционного аргумента и не будет разобран — поставь флаги первыми", rest)
		}
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("создание %s: %w", *dir, err)
	}
	st, err := store.Open(filepath.Join(*dir, "oplog.db"), oplog.Fingerprint{})
	if err != nil {
		return nil, nil, err
	}
	keys, err := admin.OpenKeyring(filepath.Join(*dir, "keys.json"))
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	return st, keys, nil
}

func defaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".qdiver"
	}
	return filepath.Join(home, ".qdiver")
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	name := fs.String("name", "", "имя сети")

	st, keys, err := workdir(fs, args)
	if err != nil {
		return err
	}
	defer st.Close()

	network := *name
	if network == "" && fs.NArg() > 0 {
		network = fs.Arg(0)
	}
	if network == "" {
		return fmt.Errorf("не задано имя сети")
	}

	fp, err := admin.InitNetwork(st, keys, network)
	if err != nil {
		return err
	}

	fmt.Printf("сеть %q создана\n\n", network)
	fmt.Printf("отпечаток сети:\n  %s\n\n", fp)
	fmt.Println("ключи владельцев:")
	for _, id := range keys.List() {
		label, scope, _ := keys.Describe(id)
		fmt.Printf("  %s  %s  %s\n", id, scope, label)
	}
	fmt.Println("\nОтпечаток попадает в конфиг каждого узла — по нему узел отличает наш журнал")
	fmt.Println("от чужого. Запасной ключ вынеси на офлайн-носитель: потеря обоих означает,")
	fmt.Println("что сеть работает, а управлять ею больше нельзя.")
	return nil
}

func cmdNodeAdd(args []string) error {
	fs := flag.NewFlagSet("node add", flag.ContinueOnError)
	id := fs.String("id", "", "идентификатор узла")
	key := fs.String("key", "", "публичный ключ узла в шестнадцатеричном виде")
	domain := fs.String("domain", "", "имя узла")
	tags := fs.String("tags", "", "свободные подписи через запятую — только для поиска в списке")
	roles := fs.String("roles", "", "роли через запятую: ingress, egress")
	endpoints := fs.String("endpoints", "", "адреса host:port через запятую")

	st, keys, err := workdir(fs, args)
	if err != nil {
		return err
	}
	defer st.Close()

	pub, err := hex.DecodeString(*key)
	if err != nil {
		return fmt.Errorf("публичный ключ: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("публичный ключ должен быть %d байт, получено %d", ed25519.PublicKeySize, len(pub))
	}

	s, err := admin.NewSession(st, keys, oplog.ScopeOwner)
	if err != nil {
		return err
	}
	node := oplog.Node{
		ID:        *id,
		PublicKey: oplog.PublicKey(pub),
		Roles:     split(*roles),
		Tags:      split(*tags),
		Domain:    *domain,
		Endpoints: split(*endpoints),
	}
	if _, err := s.Submit(oplog.KindNodeAdd, node); err != nil {
		return err
	}
	fmt.Printf("узел %s добавлен: роли %s, %s\n",
		node.ID, strings.Join(node.Roles, "+"), node.Domain)
	return nil
}

func cmdClientAdd(args []string) error {
	fs := flag.NewFlagSet("client add", flag.ContinueOnError)
	id := fs.String("id", "", "идентификатор клиента")
	label := fs.String("label", "", "подпись для человека")
	devices := fs.Int("devices", 0, "лимит устройств, 0 — без ограничения")
	traffic := fs.Int64("traffic-gb", 0, "лимит трафика в гигабайтах за период, 0 — без ограничения")
	period := fs.String("period", "", "период сброса трафика: daily, weekly, monthly")
	password := fs.String("password", "", "зашифровать бандл паролем (передавать отдельно от ссылки)")

	st, keys, err := workdir(fs, args)
	if err != nil {
		return err
	}
	defer st.Close()

	s, err := admin.NewSession(st, keys, oplog.ScopeOperator)
	if err != nil {
		return err
	}

	// Ключевая пара клиента рождается здесь: приватная часть уезжает человеку в бандл,
	// у узлов остаётся только публичная. Взлом узла поэтому не даёт выдать себя за клиента.
	signer, err := oplog.GenerateSigner()
	if err != nil {
		return err
	}

	client := oplog.Client{
		ID:        *id,
		Label:     *label,
		PublicKey: oplog.PublicKey(signer.Public()),
		Limits: oplog.Limits{
			Devices:       *devices,
			TrafficBytes:  *traffic << 30,
			TrafficPeriod: *period,
		},
	}
	if _, err := s.Submit(oplog.KindClientAdd, client); err != nil {
		return err
	}

	fmt.Printf("клиент %s заведён\n", client.ID)

	b, err := makeBundle(st.State(), client.ID, signer.Private())
	if err != nil {
		// Клиент уже в журнале, и это не откатывается. Но человек обязан узнать, почему
		// бандла нет: чаще всего в сети просто ещё нет ни одного входного узла.
		fmt.Printf("\nприватный ключ клиента:\n  %x\n", signer.Private())
		return fmt.Errorf("бандл не собрать: %w", err)
	}
	return printBundle(b, *password)
}

// cmdClientReissue выдаёт клиенту новую пару ключей и новый бандл.
//
// Единственный способ восстановить утерянный бандл: старого приватного ключа нет ни у кого,
// кроме владельца. Заодно это и есть отзыв — старый ключ перестаёт работать сразу, как только
// запись доедет до узлов.
func cmdClientReissue(args []string) error {
	fs := flag.NewFlagSet("client reissue", flag.ContinueOnError)
	id := fs.String("id", "", "идентификатор клиента")
	password := fs.String("password", "", "зашифровать бандл паролем (передавать отдельно от ссылки)")

	st, keys, err := workdir(fs, args)
	if err != nil {
		return err
	}
	defer st.Close()

	if *id == "" {
		return fmt.Errorf("не задан -id")
	}
	current, ok := st.State().Client(*id)
	if !ok {
		return fmt.Errorf("клиента %s в сети нет", *id)
	}

	s, err := admin.NewSession(st, keys, oplog.ScopeOperator)
	if err != nil {
		return err
	}

	signer, err := oplog.GenerateSigner()
	if err != nil {
		return err
	}

	// Меняется только ключ: лимиты, подпись и срок остаются теми же. Перевыпуск — это про
	// утерянный бандл, а не про пересмотр условий.
	current.PublicKey = oplog.PublicKey(signer.Public())
	if _, err := s.Submit(oplog.KindClientAdd, current); err != nil {
		return err
	}

	fmt.Printf("клиенту %s выдан новый ключ, старый больше не работает\n", current.ID)

	b, err := makeBundle(st.State(), current.ID, signer.Private())
	if err != nil {
		fmt.Printf("\nприватный ключ клиента:\n  %x\n", signer.Private())
		return fmt.Errorf("бандл не собрать: %w", err)
	}
	return printBundle(b, *password)
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	st, keys, err := workdir(fs, args)
	if err != nil {
		return err
	}
	defer st.Close()

	state := st.State()
	if state.Genesis().IsZero() {
		fmt.Println("сеть ещё не создана: qd-admin init <имя>")
		return nil
	}

	n, _ := st.Len()
	fmt.Printf("сеть %q, отпечаток %s, записей в журнале %d\n\n", state.Network(), state.Genesis(), n)

	fmt.Println("ключи администраторов:")
	for _, a := range state.Admins() {
		mine := ""
		if _, _, ok := keys.Describe(a.ID()); ok {
			mine = "  (есть у нас)"
		}
		fmt.Printf("  %s  %-8s  %s%s\n", a.ID(), a.Scope, a.Label, mine)
	}

	fmt.Println("\nузлы:")
	if len(state.Nodes()) == 0 {
		fmt.Println("  пока ни одного")
	}
	for _, node := range state.Nodes() {
		fmt.Printf("  %-12s %-14s %-28s %s\n",
			node.ID, strings.Join(node.Roles, "+"), node.Domain, strings.Join(node.Tags, ", "))
	}

	fmt.Println("\nклиенты:")
	if len(state.Clients()) == 0 {
		fmt.Println("  пока ни одного")
	}
	for _, c := range state.Clients() {
		limits := "без ограничений"
		if c.Limits.Devices > 0 || c.Limits.TrafficBytes > 0 {
			limits = fmt.Sprintf("устройств %d, трафик %d ГБ %s",
				c.Limits.Devices, c.Limits.TrafficBytes>>30, c.Limits.TrafficPeriod)
		}
		fmt.Printf("  %-12s %-20s %s\n", c.ID, c.Label, limits)
	}
	return nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	st, _, err := workdir(fs, args)
	if err != nil {
		return err
	}
	defer st.Close()

	if fs.NArg() == 0 {
		return fmt.Errorf("не задан файл")
	}
	path := fs.Arg(0)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("создание %s: %w", path, err)
	}
	defer f.Close()

	if err := st.Export(f); err != nil {
		return err
	}
	n, _ := st.Len()
	fmt.Printf("выгружено записей: %d → %s\n", n, path)
	return nil
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	st, _, err := workdir(fs, args)
	if err != nil {
		return err
	}
	defer st.Close()

	if fs.NArg() == 0 {
		return fmt.Errorf("не задан файл")
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()

	n, err := st.Import(f)
	if err != nil {
		return fmt.Errorf("влито записей %d, дальше ошибка: %w", n, err)
	}
	fmt.Printf("влито записей: %d\n", n)
	return nil
}

func split(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
