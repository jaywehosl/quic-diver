// Команда qd-client — клиент сети для настольных систем и серверов.
//
// Разбор флагов и сигналов, ничего больше: вся работа живёт в internal/client, потому что тот
// же код запускает и телефонное приложение. Различие между системами — способ получить
// интерфейс, и оно спрятано ещё ниже, в internal/tunnel.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jaywehosl/quic-diver/internal/client"
)

func main() {
	var o client.Options

	flag.StringVar(&o.Bundle, "bundle", "", "бандл сети: ссылка вида qdiver://…")
	flag.StringVar(&o.BundleFile, "bundle-file", "", "файл с бандлом")
	flag.StringVar(&o.BundlePassword, "bundle-password", "", "пароль бандла, если он зашифрован")
	flag.StringVar(&o.NodeAddr, "node", "", "один входной узел вместо бандла — для отладки")
	flag.StringVar(&o.NodeKey, "node-key", "", "публичный ключ узла")
	flag.StringVar(&o.ID, "id", "", "идентификатор клиента")
	flag.StringVar(&o.KeyHex, "key", "", "приватный ключ клиента")
	flag.StringVar(&o.Listen, "listen", "127.0.0.1:1080", "адрес входа SOCKS5; пустой — не поднимать")
	flag.BoolVar(&o.ViaExit, "via-exit", false, "гнать трафик через выходные узлы (тот самый чекбокс)")
	flag.IntVar(&o.BrutalUp, "brutal-up", -1, "потолок BRUTAL на отдачу, Мбит/с; перебивает бандл, 0 — выключить")
	flag.StringVar(&o.RulesPath, "rules", "", "файл с правилами маршрутизации (JSON)")
	flag.StringVar(&o.GeoDir, "geo-dir", "", "каталог с базами geosite/geoip")
	flag.StringVar(&o.StateDir, "state-dir", "", "каталог для сведений о сети, переживающих перезапуск")
	flag.StringVar(&o.GeoMode, "geo-update", "ask", "обновление баз: ask (спросить, если есть терминал), auto, off")
	flag.StringVar(&o.TunName, "tun", "", "поднять туннель с этим именем интерфейса")
	flag.StringVar(&o.TunAddrs, "tun-addr", "10.7.0.2/24", "адреса интерфейса через запятую")
	flag.IntVar(&o.TunMTU, "tun-mtu", 1400, "MTU интерфейса")
	flag.BoolVar(&o.TunDefault, "tun-default", true, "заворачивать в туннель весь трафик")
	flag.StringVar(&o.TunExcept, "tun-except", "", "адреса мимо туннеля через запятую (например, управляющее соединение)")
	flag.IntVar(&o.TunGuard, "tun-guard", 20, "через сколько секунд проверить связь и снять маршруты, если её нет; 0 — не проверять")
	flag.StringVar(&o.FakeRange, "fake-range", "198.18.0.0/15", "диапазон подменных адресов")
	flag.StringVar(&o.DNSUpstream, "dns", "1.1.1.1:53", "настоящий резолвер для запросов, кроме A и AAAA")
	flag.StringVar(&o.LogLevel, "log", "info", "уровень журнала")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := client.Run(ctx, o); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "qd-client:", err)
		os.Exit(1)
	}
}
