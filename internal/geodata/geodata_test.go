package geodata

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// Собираем protobuf руками — так тест проверяет разбор настоящего формата, а не
// договорённость с самим собой.

func tag(field, wire int) []byte {
	return binary.AppendUvarint(nil, uint64(field)<<3|uint64(wire))
}

func lenField(field int, body []byte) []byte {
	out := tag(field, wireBytes)
	out = binary.AppendUvarint(out, uint64(len(body)))
	return append(out, body...)
}

func varintField(field int, v uint64) []byte {
	return binary.AppendUvarint(tag(field, wireVarint), v)
}

func domainMsg(kind DomainKind, value string, attrs ...string) []byte {
	out := varintField(1, uint64(kind))
	out = append(out, lenField(2, []byte(value))...)
	for _, a := range attrs {
		attr := lenField(1, []byte(a))
		attr = append(attr, varintField(2, 1)...) // bool_value = true
		out = append(out, lenField(3, attr)...)
	}
	return out
}

func siteMsg(code string, domains ...[]byte) []byte {
	out := lenField(1, []byte(code))
	for _, d := range domains {
		out = append(out, lenField(2, d)...)
	}
	return out
}

func siteListMsg(sites ...[]byte) []byte {
	var out []byte
	for _, s := range sites {
		out = append(out, lenField(1, s)...)
	}
	return out
}

func cidrMsg(ip []byte, bits int) []byte {
	out := lenField(1, ip)
	return append(out, varintField(2, uint64(bits))...)
}

func ipSetMsg(code string, cidrs ...[]byte) []byte {
	out := lenField(1, []byte(code))
	for _, c := range cidrs {
		out = append(out, lenField(2, c)...)
	}
	return out
}

func ipListMsg(sets ...[]byte) []byte {
	var out []byte
	for _, s := range sets {
		out = append(out, lenField(1, s)...)
	}
	return out
}

func loadedSets(t *testing.T) *Sets {
	t.Helper()

	raw := siteListMsg(
		siteMsg("category-ads-all",
			domainMsg(DomainRoot, "doubleclick.net"),
			domainMsg(DomainPlain, "googlesyndication"),
		),
		siteMsg("google",
			domainMsg(DomainRoot, "google.com"),
			domainMsg(DomainRoot, "ads.google.com", "ads"),
			domainMsg(DomainFull, "mail.google.com"),
		),
		// Выражение живёт в отдельном списке: рядом с корневым google.com оно ничего не
		// проверяло бы — корень поймал бы всё раньше.
		siteMsg("regex-only",
			domainMsg(DomainRegex, `^analytics[0-9]+\.example\.com$`),
		),
	)
	sites, err := ParseSites(raw)
	if err != nil {
		t.Fatalf("разбор списков доменов: %v", err)
	}

	ipRaw := ipListMsg(
		ipSetMsg("ru",
			cidrMsg([]byte{77, 88, 0, 0}, 16),
			cidrMsg(netip.MustParseAddr("2a02:6b8::").AsSlice(), 32),
		),
		ipSetMsg("private", cidrMsg([]byte{10, 0, 0, 0}, 8)),
	)
	ips, err := ParseIPs(ipRaw)
	if err != nil {
		t.Fatalf("разбор списков подсетей: %v", err)
	}

	s := New()
	s.LoadSites(sites)
	s.LoadIPs(ips)
	return s
}

func TestRootDomainMatchesSubdomains(t *testing.T) {
	s := loadedSets(t)

	for _, d := range []string{"doubleclick.net", "stats.doubleclick.net", "a.b.doubleclick.net"} {
		if !s.Site("category-ads-all", d) {
			t.Fatalf("%s не найден в списке рекламы", d)
		}
	}
	// Чужой домен, кончающийся так же, попасть не должен.
	if s.Site("category-ads-all", "notdoubleclick.net") {
		t.Fatal("поймано чужое имя")
	}
	// И домен без завершающей точки, и с ней — одно и то же имя.
	if !s.Site("category-ads-all", "doubleclick.net.") {
		t.Fatal("имя с точкой на конце не распознано")
	}
}

func TestFullAndPlainAndRegex(t *testing.T) {
	s := loadedSets(t)

	if !s.Site("google", "mail.google.com") {
		t.Fatal("точное имя не найдено")
	}
	if !s.Site("category-ads-all", "pagead2.googlesyndication.com") {
		t.Fatal("подстрока не найдена")
	}
	if !s.Site("regex-only", "analytics7.example.com") {
		t.Fatal("выражение не сработало")
	}
	if s.Site("regex-only", "analyticsX.example.com") {
		t.Fatal("выражение поймало лишнее")
	}
	// Точное имя не должно ловить поддомены.
	if s.Site("google", "sub.mail.google.com") != s.Site("google", "google.com") {
		t.Fatal("точное имя повело себя как корневое")
	}
}

// Пометки делят большой список на части: geosite:google@ads — только реклама гугла.
func TestAttributesNarrowTheList(t *testing.T) {
	s := loadedSets(t)

	if !s.Site("google", "ads.google.com") {
		t.Fatal("домен не найден без пометки")
	}
	if !s.Site("google@ads", "ads.google.com") {
		t.Fatal("домен не найден по пометке")
	}
	if s.Site("google@ads", "google.com") {
		t.Fatal("по пометке нашлось непомеченное")
	}
}

func TestIPLists(t *testing.T) {
	s := loadedSets(t)

	if !s.IP("ru", netip.MustParseAddr("77.88.55.77")) {
		t.Fatal("адрес не найден в списке")
	}
	if s.IP("ru", netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("чужой адрес найден в списке")
	}
	if !s.IP("ru", netip.MustParseAddr("2a02:6b8::1")) {
		t.Fatal("адрес v6 не найден")
	}
	if !s.IP("private", netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("частная подсеть не найдена")
	}
	// Адрес v4, записанный как v4-in-v6, должен искаться среди четвёрок.
	if !s.IP("ru", netip.MustParseAddr("::ffff:77.88.55.77")) {
		t.Fatal("v4-in-v6 не распознан")
	}
}

func TestUnknownListIsNotAMatch(t *testing.T) {
	s := loadedSets(t)

	if s.Site("такого-нет", "doubleclick.net") {
		t.Fatal("несуществующий список что-то нашёл")
	}
	if s.HasSite("такого-нет") || s.HasIP("такого-нет") {
		t.Fatal("несуществующий список числится известным")
	}
	if !s.HasSite("google") || !s.HasIP("ru") {
		t.Fatal("существующий список не числится известным")
	}
}

// Базы обновляются чаще клиента: незнакомое поле не повод отказываться от списков, которые
// мы прекрасно понимаем.
func TestUnknownFieldsAreSkipped(t *testing.T) {
	site := siteMsg("google", domainMsg(DomainRoot, "google.com"))
	site = append(site, varintField(99, 12345)...)
	site = append(site, lenField(98, []byte("что-то из будущего"))...)

	sites, err := ParseSites(siteListMsg(site))
	if err != nil {
		t.Fatalf("разбор с незнакомыми полями: %v", err)
	}
	if len(sites) != 1 || len(sites[0].Domains) != 1 {
		t.Fatalf("список разъехался: %+v", sites)
	}
}

// Всё это приезжает файлом из сети: заявленная длина не повод выделять память.
func TestTruncatedInputIsRejected(t *testing.T) {
	raw := siteListMsg(siteMsg("google", domainMsg(DomainRoot, "google.com")))

	for _, cut := range []int{1, len(raw) / 2, len(raw) - 1} {
		if _, err := ParseSites(raw[:cut]); err == nil {
			t.Fatalf("обрезанные до %d байт данные приняты", cut)
		}
	}

	// Заявлена длина больше, чем есть данных.
	hostile := append(tag(1, wireBytes), byte(200))
	hostile = append(hostile, 1, 2, 3)
	if _, err := ParseSites(hostile); err == nil {
		t.Fatal("завышенная длина принята на веру")
	}
}

// Негодное выражение в чужой базе не должно ронять клиент: пропускается одна запись,
// остальные работают.
func TestBadRegexInDatabaseIsSkipped(t *testing.T) {
	raw := siteListMsg(siteMsg("test",
		domainMsg(DomainRegex, "["),
		domainMsg(DomainRoot, "example.com"),
	))
	sites, err := ParseSites(raw)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}

	s := New()
	s.LoadSites(sites)
	if !s.Site("test", "www.example.com") {
		t.Fatal("годная запись пропала вместе с негодной")
	}
}

func TestStatsDescribeWhatIsLoaded(t *testing.T) {
	s := loadedSets(t)
	if got := s.Stats(); got == "" {
		t.Fatal("сводка пуста")
	}
}
