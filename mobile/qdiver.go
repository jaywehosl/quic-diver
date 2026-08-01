// Package mobile — мост между телефонным приложением и ядром клиента.
//
// Тонкий намеренно: вся работа в internal/client, здесь только запуск, остановка и способ
// показать журнал человеку. Всё, что сложнее, ушло бы в код, который нельзя проверить ни
// тестом, ни на сервере, — а такого кода на телефоне и так будет достаточно.
//
// # Что делает приложение
//
// Приложение запрашивает у системы разрешение на VPN, получает от VpnService открытый
// дескриптор интерфейса и отдаёт его сюда. Адреса, маршруты и обход для самого приложения
// система расставляет по тому, что приложение попросило, — нам остаётся только читать и
// писать пакеты.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/jaywehosl/quic-diver/internal/client"
	"github.com/jaywehosl/quic-diver/internal/hwid"
	"github.com/jaywehosl/quic-diver/internal/routing"
)

// Logger принимает строки журнала. Реализуется на стороне приложения.
type Logger interface {
	// Log зовётся на каждую запись журнала. Вызовы идут из чужих потоков — на стороне
	// приложения это нужно учитывать.
	Log(line string)
}

var (
	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	logSink Logger
	state   *client.State
	control *client.Control
	prefs   = settings{geoMode: "off", brutalUp: -1}
)

// settings — то, что человек выбрал на экране настроек.
//
// Отдельно от Start намеренно: настроек будет больше, чем помещается в список аргументов, а
// мост через gomobile тем надёжнее, чем проще типы, которые через него ходят. Применяются при
// следующем запуске — менять их под работающим стеком означало бы пересобирать его на ходу.
type settings struct {
	geoMode  string
	geoDir   string
	stateDir string
	brutalUp int
	rules    []routing.Rule
	keepDNS  bool
}

// SetGeoMode задаёт, что делать с базами geosite/geoip: "off", "ask", "auto".
//
// По умолчанию выключено: базы весят под тридцать мегабайт, и качать их по сотовой сети без
// спроса нельзя.
func SetGeoMode(mode string) {
	mu.Lock()
	prefs.geoMode = mode
	mu.Unlock()
}

// SetGeoDir говорит, где держать базы.
//
// Задавать обязательно: домашнего каталога на телефоне нет, и без этого клиенту некуда их
// класть. Приложение отдаёт сюда свой getFilesDir.
func SetGeoDir(dir string) {
	mu.Lock()
	prefs.geoDir = dir
	mu.Unlock()
}

// SetStateDir говорит, где держать сведения о сети между запусками.
//
// Отдельно от каталога баз: базы весят тридцать мегабайт и им место там, где их не жалко, а
// это несколько килобайт, без которых клиент после добавления узла ходил бы по устаревшему
// списку до самой перевыдачи ссылки. Приложение отдаёт сюда свой getFilesDir.
func SetStateDir(dir string) {
	mu.Lock()
	prefs.stateDir = dir
	mu.Unlock()
}

// SetBrutalUp перебивает потолок отдачи, пришедший из сети. Отрицательное возвращает сетевой.
func SetBrutalUp(mbps int) {
	mu.Lock()
	prefs.brutalUp = mbps
	mu.Unlock()
}

// SetKeepDNS включает перехват шифрованного DNS.
//
// Браузер со включённым DoH разрешает имена сам, минуя туннель: у потоков не остаётся имён, и
// правила по доменам перестают работать целиком — молча. Перехват возвращает разрешение имён
// нам: известные резолверы DoH получают отказ, соединения на порт DoT обрываются, и браузер
// откатывается на системный резолвер.
func SetKeepDNS(on bool) {
	mu.Lock()
	prefs.keepDNS = on
	mu.Unlock()
}

// SetRules задаёт правила маршрутизации: массив JSON.
//
// Правила принадлежат человеку и живут на устройстве — сеть их не назначает (ТЗ ст. 36).
// Формат каждого правила:
//
//	{"match": ["domain:yandex.ru"], "action": "direct", "comment": "…", "force": false}
//
// action — "direct" (наружу на входном узле), "egress" (через выходной) или "block"
// (оборвать: RST потоку, NXDOMAIN имени). force означает «соблюдать всегда»: такое правило не
// перебивается никаким другим.
//
// Работает и при запущенном клиенте: правила применяются сразу, а открытые потоки
// закрываются — иначе только что написанное правило не подействовало бы на то, что человек
// видит перед собой. Ошибка означает, что правило негодное; тогда прежние остаются в силе.
func SetRules(rulesJSON string) error {
	rules, err := parseRules(rulesJSON)
	if err != nil {
		return err
	}

	mu.Lock()
	prefs.rules = rules
	ctl := control
	mu.Unlock()

	if ctl == nil {
		// Клиент не запущен: правила применятся при следующем запуске, и это не ошибка.
		return nil
	}
	return ctl.SetRules(rules)
}

// parseRules разбирает и проверяет правила, не применяя их.
//
// Отдельно, чтобы приложение могло проверить, что человек написал, до того как это станет
// действующим набором.
func parseRules(rulesJSON string) ([]routing.Rule, error) {
	s := strings.TrimSpace(rulesJSON)
	if s == "" || s == "null" {
		return nil, nil
	}

	var rules []routing.Rule
	if err := json.Unmarshal([]byte(s), &rules); err != nil {
		return nil, fmt.Errorf("разбор правил: %w", err)
	}
	// Сборка движка на выброс — самая честная проверка: те же условия, тот же разбор, те же
	// сообщения об ошибках, что и при настоящем применении.
	if _, err := routing.New(rules, routing.ActionDirect, slog.New(slog.DiscardHandler)); err != nil {
		return nil, err
	}
	return rules, nil
}

// CheckRules проверяет правила, ничего не применяя. Пустой ответ означает, что всё в порядке.
func CheckRules(rulesJSON string) string {
	if _, err := parseRules(rulesJSON); err != nil {
		return err.Error()
	}
	return ""
}

// GeoStatus отдаёт состояние баз строкой JSON, никуда не ходя.
//
//	{"installed":"202607302259","sites":1538,"ips":260}
//
// Пустой installed означает, что баз нет и правила со списками не работают. Спрашивается
// перед входом в маршрутизацию: там это первое, что нужно знать.
func GeoStatus() string {
	mu.Lock()
	dir := prefs.geoDir
	mu.Unlock()
	return client.LocalGeo(dir, slog.New(newHandler())).JSON()
}

// FetchGeo скачивает базы, не поднимая туннеля.
//
// Связь с сетью поднимается своя, разрешение на VPN для этого не нужно: трафик идёт обычным
// сокетом приложения. Вызов долгий — двадцать восемь мегабайт, — и звать его с главного
// потока нельзя.
func FetchGeo(bundle, password string) error {
	mu.Lock()
	o := client.Options{
		Bundle:         bundle,
		BundlePassword: password,
		GeoDir:         prefs.geoDir,
		StateDir:       prefs.stateDir,
		GeoMode:        "auto",
		Log:            slog.New(newHandler()),
	}
	mu.Unlock()

	if bundle == "" {
		return errors.New("не задан бандл сети")
	}
	_, err := client.FetchGeo(context.Background(), o)
	return err
}

// NetworkStatus — что клиент помнит о сети, не спрашивая её.
//
// Отвечает JSON: {"network":…, "nodes":…, "egress":…, "saved_unix":…}. Пустое имя означает, что
// сеть ещё не рассказывала о себе, и клиент пойдёт по узлам из ссылки.
func NetworkStatus() string {
	mu.Lock()
	dir := prefs.stateDir
	mu.Unlock()
	return client.LocalNetwork(dir, slog.New(newHandler())).JSON()
}

// RefreshNetwork спрашивает у сети свежий список узлов и записывает его.
//
// Это кнопка «обновить сейчас» (ТЗ ст. 32, решение 007 §4). Связь поднимается своя, разрешение
// на VPN не нужно. Работающему клиенту вызов не требуется: он получает то же самое сам.
//
// Отвечает тем же JSON, что NetworkStatus, плюс "changed" — изменился ли состав.
func RefreshNetwork(bundle, password string) (string, error) {
	mu.Lock()
	o := client.Options{
		Bundle:         bundle,
		BundlePassword: password,
		StateDir:       prefs.stateDir,
		Log:            slog.New(newHandler()),
	}
	mu.Unlock()

	if bundle == "" {
		return "", errors.New("не задан бандл сети")
	}

	// У владельца спрашивать сеть не у кого и незачем: он её и есть. Узлы лежат в его журнале,
	// и это источник более свежий, чем любой снапшот, — снапшот собирается из журнала, только
	// чужого и по дороге.
	if status, ok, err := refreshFromOwnJournal(); ok {
		if err != nil {
			return "", err
		}
		return status, nil
	}
	status, err := client.RefreshNetwork(context.Background(), o)
	if err != nil {
		return "", err
	}
	return status.JSON(), nil
}

// GeoLists перечисляет списки из загруженных баз: kind — "site" либо "ip".
//
// Имена отдаются как есть, без перевода: их полторы тысячи, они приходят из чужой базы и
// меняются вместе с ней. Отбор и поиск — дело экрана.
func GeoLists(kind string) string {
	mu.Lock()
	dir := prefs.geoDir
	mu.Unlock()

	sites, ips, err := client.GeoLists(dir, slog.New(newHandler()))
	if err != nil {
		return "[]"
	}

	out := sites
	if kind == "ip" {
		out = ips
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

// SetDeviceID называет устройство.
//
// Задавать обязательно: общесистемного идентификатора машины на Android нет, и без этого
// телефон приходит на узел безымянным — а безымянное устройство лимитом устройств не
// считается вовсе. Приложение отдаёт сюда Settings.Secure.ANDROID_ID.
//
// Наружу уходит не само значение, а его отпечаток (см. internal/hwid).
func SetDeviceID(id string) { hwid.Set(id) }

// SetLogger задаёт, куда уходит журнал. Пустой означает, что журнал теряется.
func SetLogger(l Logger) {
	mu.Lock()
	logSink = l
	mu.Unlock()
}

// Start поднимает клиента на готовом дескрипторе.
//
// bundle — ссылка вида qdiver://…, password — её пароль, если он есть. fd приходит от
// VpnService; закрывать его будет ядро при остановке.
//
// Возвращается сразу, не дожидаясь связи: приложение не должно висеть на главном потоке,
// пока идёт гонка входных узлов.
func Start(fd int, bundle, password string, viaExit bool, mtu int) error {
	mu.Lock()
	defer mu.Unlock()

	if cancel != nil {
		return errors.New("клиент уже работает")
	}
	if fd <= 0 {
		return errors.New("не задан дескриптор интерфейса")
	}
	if bundle == "" {
		return errors.New("не задан бандл сети")
	}

	ctx, stop := context.WithCancel(context.Background())
	st := client.NewState()
	ctl := client.NewControl()
	opts := client.Options{
		State:          st,
		Control:        ctl,
		Bundle:         bundle,
		BundlePassword: password,
		ViaExit:        viaExit,
		TunFD:          fd,
		TunMTU:         mtu,
		BrutalUp:       prefs.brutalUp,
		GeoMode:        prefs.geoMode,
		GeoDir:         prefs.geoDir,
		StateDir:       prefs.stateDir,
		Rules:          prefs.rules,
		KeepDNS:        prefs.keepDNS,
		// Входа SOCKS на телефоне нет: весь трафик и так идёт туннелем, а открытый порт на
		// устройстве, которое ходит по чужим сетям, — лишний способ получить неприятность.
		Listen: "",
		// Сторож туннеля выключен: снимать маршруты, которые расставила система, клиент здесь
		// не вправе — их владелец VpnService, и отбирает он их сам.
		TunGuard: 0,
		Log:      slog.New(newHandler()),
	}

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		if err := client.Run(ctx, opts); err != nil && ctx.Err() == nil {
			emit("клиент остановился: " + err.Error())
		}
	}()

	cancel, done, state, control = stop, finished, st, ctl
	return nil
}

// SetViaExit переключает «через выходные узлы» при работающем клиенте.
//
// Работает сразу, без переподключения: это умолчание маршрутизации, и меняется оно у движка
// правил на ходу. Уже открытые соединения остаются там, где были, — переносить живой поток
// на другой узел нельзя, да и незачем.
//
// Отвечает false, когда клиент не запущен: тогда выбор просто запомнит приложение и применит
// его при следующем запуске.
func SetViaExit(on bool) bool {
	mu.Lock()
	ctl := control
	mu.Unlock()
	return ctl.SetViaExit(on)
}

// Status отдаёт состояние клиента одной строкой JSON.
//
// Одним вызовом и одним куском намеренно: приложение спрашивает его раз в секунду, и дюжина
// отдельных вызовов через мост стоила бы дороже самого ответа. А скорость приложение считает
// само — по разнице двух опросов оно знает, сколько между ними прошло, а ядро не знает.
func Status() string {
	mu.Lock()
	st := state
	running := cancel != nil
	mu.Unlock()

	stats := st.Stats()
	if !running {
		// Ядро остановлено: показывать «подключено» по остаткам прошлого запуска нельзя.
		stats.Connected = false
	}

	raw, err := json.Marshal(stats)
	if err != nil {
		return `{"connected":false}`
	}
	return string(raw)
}

// Network отдаёт то, что клиент знает о сети: правила, узлы, потолки скорости.
//
// Отдельно от Status намеренно. Status спрашивают раз в секунду ради чисел, а это меняется
// раз в сутки и весит на порядок больше — гонять его через мост шестьдесят раз в минуту
// незачем. Спрашивается, когда человек открыл настройки.
func Network() string {
	mu.Lock()
	st := state
	mu.Unlock()

	raw, err := json.Marshal(st.Network())
	if err != nil {
		return `{"rules":[],"nodes":[]}`
	}
	return string(raw)
}

// Stop останавливает клиента и ждёт, пока тот действительно закончит.
//
// Ждёт намеренно: приложение вправе сразу после этого закрыть дескриптор, а закрывать его
// под работающим стеком — верный способ получить отказ в неожиданном месте.
func Stop() {
	mu.Lock()
	stop, finished := cancel, done
	cancel, done, control = nil, nil, nil
	mu.Unlock()

	if stop == nil {
		return
	}
	stop()
	<-finished
}

// Running говорит, работает ли клиент.
func Running() bool {
	mu.Lock()
	defer mu.Unlock()
	return cancel != nil
}

// Version — версия ядра, чтобы приложение могло её показать.
func Version() string { return "0.1.0" }

func emit(line string) {
	mu.Lock()
	sink := logSink
	mu.Unlock()

	if sink != nil {
		sink.Log(line)
	}
}
