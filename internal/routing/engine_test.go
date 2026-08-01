package routing

import (
	"log/slog"
	"net/netip"
	"strings"
	"testing"
)

func engine(t *testing.T, fallback Action, rules ...Rule) *Engine {
	t.Helper()
	e, err := New(rules, fallback, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("сборка движка: %v", err)
	}
	return e
}

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("адрес %q: %v", s, err)
	}
	return a
}

// Главное правило из уточнения заказчика: чекбокс задаёт умолчание, правила его
// переопределяют каждое для себя.
func TestFallbackIsOverriddenPerFlow(t *testing.T) {
	e := engine(t, ActionEgress,
		Rule{Match: []string{"domain:yandex.ru"}, Action: string(ActionDirect)},
	)

	yandex := e.Decide(Flow{Domain: "yandex.ru"})
	if yandex.Action != ActionDirect {
		t.Fatalf("яндекс пошёл через выход: %s", yandex)
	}
	if yandex.ByDefault() {
		t.Fatal("решение по яндексу должно быть от правила, а не от умолчания")
	}

	other := e.Decide(Flow{Domain: "example.com"})
	if other.Action != ActionEgress {
		t.Fatalf("остальное не пошло через выход: %s", other)
	}
	if !other.ByDefault() {
		t.Fatal("решение по остальному должно быть от умолчания")
	}
}

// Правило по имени сильнее правила по процессу — случай заказчика дословно.
//
// «Если я выбрал chrome.exe через выходные узлы и также добавил правило *yandex.ru через
// входные узлы, значит любой *yandex.ru через chrome.exe должен открываться через входные
// узлы. И точка.»
func TestDomainRuleBeatsProcessRule(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"process:chrome.exe"}, Action: string(ActionEgress)},
		Rule{Match: []string{"domain:yandex.ru"}, Action: string(ActionDirect)},
	)

	// Яндекс в хроме: совпали оба правила, побеждает то, что про имя.
	both := e.Decide(Flow{Domain: "mail.yandex.ru", Process: "chrome.exe"})
	if both.Action != ActionDirect {
		t.Fatalf("яндекс в хроме ушёл на выход: %s", both)
	}
	if both.Rule != 2 {
		t.Fatalf("сработало правило %d, ждали второе (по имени): %s", both.Rule, both)
	}

	// Всё остальное в хроме — по правилу процесса.
	other := e.Decide(Flow{Domain: "youtube.com", Process: "chrome.exe"})
	if other.Action != ActionEgress {
		t.Fatalf("прочее в хроме не ушло на выход: %s", other)
	}

	// Порядок в списке при этом ничего не решает: перевернём — ответ тот же.
	reversed := engine(t, ActionDirect,
		Rule{Match: []string{"domain:yandex.ru"}, Action: string(ActionDirect)},
		Rule{Match: []string{"process:chrome.exe"}, Action: string(ActionEgress)},
	)
	if got := reversed.Decide(Flow{Domain: "mail.yandex.ru", Process: "chrome.exe"}); got.Action != ActionDirect {
		t.Fatalf("от перестановки правил ответ изменился: %s", got)
	}
}

// Настоящий адрес нужен только правилам по подсетям.
//
// В туннеле имя разрешается подменным адресом, и узнать настоящий стоит похода к резолверу.
// Платить за него там, где он ни на что не влияет, незачем: правила по именам и процессам
// обходятся тем, что известно и так.
func TestNeedsAddrOnlyForAddressRules(t *testing.T) {
	cases := []struct {
		name  string
		match string
		want  bool
	}{
		{"по имени", "domain:example.com", false},
		{"по списку имён", "geosite:category-ru", false},
		{"по процессу", "process:chrome.exe", false},
		{"по подсети", "ip:203.0.113.0/24", true},
		{"по списку подсетей", "geoip:ru", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := engine(t, ActionDirect, Rule{Match: []string{c.match}, Action: string(ActionDirect)})
			if got := e.NeedsAddr(); got != c.want {
				t.Fatalf("NeedsAddr для %q дал %v, ждали %v", c.match, got, c.want)
			}
		})
	}

	// Без правил вовсе ходить тем более незачем.
	if engine(t, ActionDirect).NeedsAddr() {
		t.Fatal("пустой набор правил требует адрес")
	}
}

// Выключенное правило по подсети адреса не требует: в движок оно не попало.
func TestDisabledAddressRuleNeedsNoAddr(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"geoip:ru"}, Action: string(ActionDirect), Off: true},
	)
	if e.NeedsAddr() {
		t.Fatal("выключенное правило заставляет ходить к резолверу")
	}
}

// Выключенное правило не работает, но своё место в списке держит: номера соседей не съезжают.
//
// Иначе объяснение «правило 3» после выключения одной строки указывало бы на другую, и
// человек искал бы причину не там.
func TestDisabledRuleIsSkippedButKeepsNumbering(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"domain:first.example"}, Action: string(ActionBlock)},
		Rule{Match: []string{"domain:off.example"}, Action: string(ActionBlock), Off: true},
		Rule{Match: []string{"domain:third.example"}, Action: string(ActionEgress)},
	)

	// Выключенное не срабатывает вовсе.
	if got := e.Decide(Flow{Domain: "off.example"}); got.Action != ActionDirect || !got.ByDefault() {
		t.Fatalf("выключенное правило сработало: %s", got)
	}
	// Соседи сохранили свои номера.
	if got := e.Decide(Flow{Domain: "third.example"}); got.Rule != 3 {
		t.Fatalf("номер съехал после выключенного: %s", got)
	}
	if got := e.Decide(Flow{Domain: "first.example"}); got.Rule != 1 {
		t.Fatalf("номер первого правила изменился: %s", got)
	}
}

// Выключенное правило всё равно проверяется: негодное остаётся негодным, сколько его ни
// выключай, — иначе ошибка всплыла бы при включении, когда человек уже забыл, что писал.
func TestDisabledRuleIsStillValidated(t *testing.T) {
	_, err := New([]Rule{
		{Match: []string{"такого-вида-нет:значение"}, Action: string(ActionDirect), Off: true},
	}, ActionDirect, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("негодное выключенное правило приняли")
	}
}

// Между именем и адресом сильнее имя: оно точнее говорит, куда человек идёт.
func TestDomainRuleBeatsAddressRule(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"ip:203.0.113.0/24"}, Action: string(ActionEgress)},
		Rule{Match: []string{"domain:example.com"}, Action: string(ActionBlock)},
	)

	got := e.Decide(Flow{Domain: "example.com", Addr: addr(t, "203.0.113.7")})
	if got.Action != ActionBlock {
		t.Fatalf("правило по адресу перебило правило по имени: %s", got)
	}
}

// Адрес сильнее процесса: процесс не говорит о месте назначения вовсе.
func TestAddressRuleBeatsProcessRule(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"process:curl"}, Action: string(ActionEgress)},
		Rule{Match: []string{"ip:203.0.113.0/24"}, Action: string(ActionBlock)},
	)

	got := e.Decide(Flow{Addr: addr(t, "203.0.113.7"), Process: "curl"})
	if got.Action != ActionBlock {
		t.Fatalf("правило по процессу перебило правило по адресу: %s", got)
	}
}

// Флаг «соблюдать всегда» ставит правило выше всех ступеней.
//
// Ступени покрывают обычные случаи, но человеку нужен способ сказать «вот это — без
// исключений», не перестраивая весь список.
func TestForceRuleOutranksEverything(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"process:torrent"}, Action: string(ActionEgress), Force: true},
		Rule{Match: []string{"domain:tracker.example"}, Action: string(ActionDirect)},
	)

	got := e.Decide(Flow{Domain: "tracker.example", Process: "torrent"})
	if got.Action != ActionEgress {
		t.Fatalf("правило со флагом «всегда» проиграло правилу по имени: %s", got)
	}
	if !got.Force {
		t.Fatalf("решение не помечено как принятое по неперебиваемому правилу: %+v", got)
	}
	if !strings.Contains(got.String(), "всегда") {
		t.Fatalf("объяснение молчит о флаге: %s", got)
	}
}

// Два неперебиваемых правила: побеждает то, что раньше в списке.
func TestTwoForceRulesResolveByOrder(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"process:app"}, Action: string(ActionEgress), Force: true},
		Rule{Match: []string{"domain:example.com"}, Action: string(ActionBlock), Force: true},
	)

	got := e.Decide(Flow{Domain: "example.com", Process: "app"})
	if got.Action != ActionEgress || got.Rule != 1 {
		t.Fatalf("из двух неперебиваемых победило не первое: %s", got)
	}
}

// Обратный случай: чекбокс снят, а правило гонит через выход.
func TestRuleCanSendToExitWhenDefaultIsDirect(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"domain:youtube.com"}, Action: string(ActionEgress)},
	)

	if got := e.Decide(Flow{Domain: "www.youtube.com"}); got.Action != ActionEgress {
		t.Fatalf("правило не переопределило умолчание: %s", got)
	}
	if got := e.Decide(Flow{Domain: "example.com"}); got.Action != ActionDirect {
		t.Fatalf("остальное ушло не туда: %s", got)
	}
}

// Правило для домена обязано ловить поддомены и не ловить чужой домен, кончающийся так же.
func TestDomainMatchesSubdomainsButNotLookalikes(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"domain:example.com"}, Action: string(ActionBlock)},
	)

	for _, d := range []string{"example.com", "www.example.com", "a.b.example.com"} {
		if got := e.Decide(Flow{Domain: d}); got.Action != ActionBlock {
			t.Fatalf("%s не поймано: %s", d, got)
		}
	}
	for _, d := range []string{"notexample.com", "example.com.evil.net", "example.org"} {
		if got := e.Decide(Flow{Domain: d}); got.Action == ActionBlock {
			t.Fatalf("%s поймано по ошибке — это чужой сайт", d)
		}
	}
}

// Порядок значим: побеждает первое совпавшее правило.
func TestFirstMatchWins(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"domain:ads.example.com"}, Action: string(ActionBlock)},
		Rule{Match: []string{"domain:example.com"}, Action: string(ActionEgress)},
	)

	if got := e.Decide(Flow{Domain: "ads.example.com"}); got.Action != ActionBlock {
		t.Fatalf("сработало не первое правило: %s", got)
	}
	if got := e.Decide(Flow{Domain: "www.example.com"}); got.Action != ActionEgress {
		t.Fatalf("сработало не второе правило: %s", got)
	}
}

// Условия внутри правила соединены «или»: имя известно не всегда, и правило, требующее
// совпадения всех условий, промахивалось бы там, где домена нет.
func TestConditionsInsideRuleAreOr(t *testing.T) {
	e := engine(t, ActionEgress,
		Rule{
			Match:  []string{"domain:yandex.ru", "ip:77.88.55.0/24"},
			Action: string(ActionDirect),
		},
	)

	byName := e.Decide(Flow{Domain: "yandex.ru", Addr: addr(t, "1.2.3.4")})
	if byName.Action != ActionDirect {
		t.Fatalf("не поймано по имени: %s", byName)
	}
	byAddr := e.Decide(Flow{Addr: addr(t, "77.88.55.77")})
	if byAddr.Action != ActionDirect {
		t.Fatalf("не поймано по адресу, хотя домен неизвестен: %s", byAddr)
	}
}

func TestMatchersCoverTheUsualForms(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"full:exact.com"}, Action: string(ActionBlock)},
		Rule{Match: []string{"keyword:doubleclick"}, Action: string(ActionBlock)},
		Rule{Match: []string{`regexp:^ads[0-9]*\.`}, Action: string(ActionBlock)},
		Rule{Match: []string{"port:25"}, Action: string(ActionBlock)},
		Rule{Match: []string{"process:torrent"}, Action: string(ActionEgress)},
		Rule{Match: []string{"ip:10.0.0.0/8"}, Action: string(ActionDirect)},
	)

	cases := []struct {
		name string
		flow Flow
		want Action
	}{
		{"точное имя", Flow{Domain: "exact.com"}, ActionBlock},
		{"точное имя не ловит поддомен", Flow{Domain: "www.exact.com"}, ActionDirect},
		{"подстрока", Flow{Domain: "stats.doubleclick.net"}, ActionBlock},
		{"выражение", Flow{Domain: "ads7.example.com"}, ActionBlock},
		{"порт", Flow{Domain: "mail.example.com", Port: 25}, ActionBlock},
		{"процесс", Flow{Domain: "tracker.example.com", Process: "torrent"}, ActionEgress},
		{"подсеть", Flow{Addr: addr(t, "10.1.2.3")}, ActionDirect},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := e.Decide(c.flow); got.Action != c.want {
				t.Fatalf("получили %s, ждали %s", got, c.want)
			}
		})
	}
}

// sets — поддельные базы.
type sets struct {
	site map[string][]string
	ip   map[string][]netip.Prefix
}

func (s sets) Site(list, domain string) bool {
	for _, d := range s.site[list] {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

func (s sets) IP(list string, a netip.Addr) bool {
	for _, p := range s.ip[list] {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (s sets) HasSite(list string) bool { _, ok := s.site[list]; return ok }
func (s sets) HasIP(list string) bool   { _, ok := s.ip[list]; return ok }

// Без баз правила по доменам и подсетям работают, а geosite и geoip — нет. Молчать об этом
// нельзя: человек будет считать, что реклама режется, а она не режется.
func TestWithoutSetsGeoRulesAreInactiveAndSaidSo(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"geosite:category-ads-all"}, Action: string(ActionBlock)},
		Rule{Match: []string{"domain:example.com"}, Action: string(ActionEgress)},
	)

	if got := e.Decide(Flow{Domain: "ads.doubleclick.net"}); got.Action != ActionDirect {
		t.Fatalf("geosite сработал без баз: %s", got)
	}
	if got := e.Decide(Flow{Domain: "example.com"}); got.Action != ActionEgress {
		t.Fatalf("правило по домену перестало работать без баз: %s", got)
	}

	inactive := e.Inactive()
	if len(inactive) != 1 || !strings.Contains(inactive[0], "geosite:category-ads-all") {
		t.Fatalf("о неработающем правиле не сказано: %v", inactive)
	}
}

func TestWithSetsGeoRulesWork(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"geosite:category-ads-all"}, Action: string(ActionBlock)},
		Rule{Match: []string{"geoip:ru"}, Action: string(ActionDirect)},
		Rule{Match: []string{"domain:example.com"}, Action: string(ActionEgress)},
	)
	e.SetSets(sets{
		site: map[string][]string{"category-ads-all": {"doubleclick.net"}},
		ip:   map[string][]netip.Prefix{"ru": {netip.MustParsePrefix("77.88.0.0/16")}},
	})

	if got := e.Decide(Flow{Domain: "stats.doubleclick.net"}); got.Action != ActionBlock {
		t.Fatalf("реклама не поймана: %s", got)
	}
	if got := e.Decide(Flow{Addr: addr(t, "77.88.55.77")}); got.Action != ActionDirect {
		t.Fatalf("российская подсеть не поймана: %s", got)
	}
	if len(e.Inactive()) != 0 {
		t.Fatalf("с базами не должно быть неработающих правил: %v", e.Inactive())
	}
}

// База загружена, но нужного списка в ней нет — это тоже неработающее правило.
func TestMissingListIsReportedToo(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"geosite:такого-нет"}, Action: string(ActionBlock)},
	)
	e.SetSets(sets{site: map[string][]string{"category-ads-all": {"doubleclick.net"}}})

	if len(e.Inactive()) != 1 {
		t.Fatalf("о пропавшем списке не сказано: %v", e.Inactive())
	}
}

// Чекбокс переключается на лету, вместе с ним меняется судьба всего, что не попало в правила.
func TestFallbackSwitchesOnTheFly(t *testing.T) {
	e := engine(t, ActionDirect,
		Rule{Match: []string{"domain:yandex.ru"}, Action: string(ActionDirect)},
	)
	if got := e.Decide(Flow{Domain: "example.com"}); got.Action != ActionDirect {
		t.Fatalf("до переключения: %s", got)
	}

	if err := e.SetFallback(ActionEgress); err != nil {
		t.Fatalf("переключение: %v", err)
	}
	if got := e.Decide(Flow{Domain: "example.com"}); got.Action != ActionEgress {
		t.Fatalf("после переключения: %s", got)
	}
	// Правило как гнало яндекс напрямую, так и гонит.
	if got := e.Decide(Flow{Domain: "yandex.ru"}); got.Action != ActionDirect {
		t.Fatalf("правило пострадало от переключения умолчания: %s", got)
	}
}

// Умолчанием не может быть блокировка: клиент, забывший правило, потерял бы весь трафик.
func TestBlockCannotBeDefault(t *testing.T) {
	if _, err := New(nil, ActionBlock, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("блокировка принята умолчанием")
	}
	e := engine(t, ActionDirect)
	if err := e.SetFallback(ActionBlock); err == nil {
		t.Fatal("блокировка принята умолчанием на лету")
	}
}

func TestBadRulesAreRejected(t *testing.T) {
	cases := map[string]Rule{
		"выдуманное действие": {Match: []string{"domain:x.com"}, Action: "через-варшаву"},
		"пустое условие":      {Match: nil, Action: string(ActionDirect)},
		"негодный вид":        {Match: []string{"страна:ru"}, Action: string(ActionDirect)},
		"негодная подсеть":    {Match: []string{"ip:не-адрес"}, Action: string(ActionDirect)},
		"негодное выражение":  {Match: []string{"regexp:["}, Action: string(ActionDirect)},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New([]Rule{r}, ActionDirect, slog.New(slog.DiscardHandler)); err == nil {
				t.Fatal("негодное правило принято")
			}
		})
	}
}

// Решение должно объяснять себя: человек, у которого сайт пошёл не туда, обязан увидеть,
// какое правило сработало.
func TestDecisionExplainsItself(t *testing.T) {
	e := engine(t, ActionEgress,
		Rule{Match: []string{"domain:yandex.ru"}, Action: string(ActionDirect)},
	)
	got := e.Decide(Flow{Domain: "mail.yandex.ru"})
	if got.Rule != 1 || !strings.Contains(got.Reason, "yandex.ru") {
		t.Fatalf("решение не объясняет себя: %+v", got)
	}
	if !strings.Contains(got.String(), "правило 1") {
		t.Fatalf("описание решения непонятно: %s", got)
	}
}
