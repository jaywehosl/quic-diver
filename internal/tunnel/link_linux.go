//go:build linux

package tunnel

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
)

// Настройка интерфейса на Linux.
//
// Через утилиту `ip`, а не netlink: команд четыре, каждая видна в логе целиком, и человек,
// разбирающий поломку, может повторить их руками. Netlink здесь дал бы лишь экономию на
// запуске процесса, которая случается один раз за жизнь клиента.

// Configure поднимает интерфейс, вешает адреса и заворачивает в него весь трафик.
//
// except — адреса, до которых маршрут остаётся прежним. Это узлы сети: без исключения
// соединение с узлом пошло бы в туннель, который сам через это соединение и работает.
// Порядок обязателен — сперва исключения, потом маршрут по умолчанию, иначе связь рвётся
// в промежутке между двумя командами.
func (t *Tunnel) Configure(except []netip.Addr, defaultRoute bool) error {
	if err := run("ip", "link", "set", "dev", t.name, "mtu", strconv.Itoa(t.cfg.MTU)); err != nil {
		return err
	}
	if err := run("ip", "link", "set", "dev", t.name, "up"); err != nil {
		return err
	}

	for _, p := range t.cfg.Addrs {
		family := "-4"
		if p.Addr().Is6() {
			family = "-6"
		}
		if err := run("ip", family, "addr", "add", p.String(), "dev", t.name); err != nil {
			return err
		}
	}

	if !defaultRoute {
		return nil
	}

	gw, err := defaultGateway()
	if err != nil {
		return fmt.Errorf("tunnel: не найден прежний шлюз, без него исключения не поставить: %w", err)
	}
	for _, addr := range except {
		if addr.Is6() {
			// Узлы держим по v4: одного семейства достаточно, а два исключения на узел
			// удваивают шанс промахнуться.
			continue
		}
		args := []string{"route", "replace", addr.String() + "/32", "via", gw.addr, "dev", gw.dev}
		if gw.onlink {
			// У многих хостеров машина стоит с маской /32, а шлюз лежит в чужой подсети —
			// в такой раскладке ядро откажет с «Nexthop has invalid gateway», пока не
			// сказать ему onlink. Прежний маршрут по умолчанию именно такой, и наш
			// обязан его повторить.
			args = append(args, "onlink")
		}
		if err := run("ip", args...); err != nil {
			return err
		}
	}

	// Две половинки вместо 0.0.0.0/0: так наш маршрут точнее прежнего по длине префикса и
	// побеждает без возни с метриками, а прежний остаётся на месте — его не надо
	// восстанавливать при выходе.
	for _, dst := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := run("ip", "route", "replace", dst, "dev", t.name); err != nil {
			return err
		}
	}
	return nil
}

// AddRoute заворачивает подсеть в туннель.
//
// Нужно для диапазона подменных адресов: пакеты на них обязаны дойти до стека, иначе имя,
// выданное службой имён, никуда не приведёт.
func (t *Tunnel) AddRoute(p netip.Prefix) error {
	return run("ip", "route", "replace", p.String(), "dev", t.name)
}

// Deconfigure убирает за собой маршруты-исключения.
//
// Сам интерфейс с его адресами и половинками маршрута исчезает вместе с процессом, а вот
// исключения прописаны в общей таблице и остались бы висеть.
func (t *Tunnel) Deconfigure(except []netip.Addr) {
	for _, addr := range except {
		if addr.Is6() {
			continue
		}
		_ = run("ip", "route", "del", addr.String()+"/32")
	}
}

// gateway — прежний маршрут по умолчанию целиком.
//
// Одного адреса шлюза мало: нужны ещё устройство и признак onlink, иначе исключение для
// узла не поставить на машинах, где шлюз лежит вне подсети хоста.
type gateway struct {
	addr   string
	dev    string
	onlink bool
}

// defaultGateway достаёт прежний маршрут по умолчанию.
func defaultGateway() (gateway, error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return gateway{}, err
	}

	var gw gateway
	fields := splitFields(string(out))
	for i, f := range fields {
		switch f {
		case "via":
			if i+1 < len(fields) {
				gw.addr = fields[i+1]
			}
		case "dev":
			if i+1 < len(fields) {
				gw.dev = fields[i+1]
			}
		case "onlink":
			gw.onlink = true
		}
	}
	if gw.addr == "" || gw.dev == "" {
		return gateway{}, fmt.Errorf("tunnel: в таблице нет маршрута по умолчанию")
	}
	return gw, nil
}

func splitFields(s string) []string {
	var out []string
	field := ""
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r':
			if field != "" {
				out = append(out, field)
				field = ""
			}
		default:
			field += string(r)
		}
	}
	if field != "" {
		out = append(out, field)
	}
	return out
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tunnel: %s %v: %w: %s", name, args, err, out)
	}
	return nil
}
