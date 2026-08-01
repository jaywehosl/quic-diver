package dnsproxy

import "strings"

// Шифрованный DNS мимо туннеля.
//
// # Зачем вмешиваться
//
// Браузер со включённым DoH разрешает имена сам, по HTTPS, к своему провайдеру. Для нас это
// значит, что имени у потока не будет вовсе: приложение получит настоящий адрес и пойдёт на
// него напрямую. Рушится сразу всё, что держится на именах, — правила по доменам, категории
// geosite, блокировки, подменные адреса.
//
// Со стороны это выглядит так: человек написал «реклама — блокировать», реклама не режется, и
// понять почему нельзя ничем.
//
// Просить людей выключать DoH руками — не решение: половина не знает, где это, а другая
// половина забудет при обновлении браузера.
//
// # Что делается
//
// Три вещи, и все — стандартные способы, а не трюки.
//
// Первое: канареечный домен. Firefox спрашивает `use-application-dns.net` и, получив
// NXDOMAIN, выключает DoH сам — механизм придуман Mozilla ровно для сетей, где разрешение
// имён делает кто-то другой.
//
// Второе: имена известных провайдеров DoH получают NXDOMAIN. Браузер, не сумевший разрешить
// адрес своего резолвера, откатывается на системный — то есть на нас. Это обычный отказ в
// разрешении имени, а не подмена ответа: мы не притворяемся чужим сервером и ничего не
// расшифровываем.
//
// Третье лежит в туннеле, а не здесь: соединения на порт 853 (DNS over TLS) обрываются.
//
// # Чего это не даёт
//
// Приложение, которое ходит к DoH по адресу-литералу, обойдёт всё это: имени в таком
// соединении нет, и разрешать нечего. Против него работает только правило по подсети, и это
// уже выбор человека, а не наше умолчание.

// DoTPort — порт DNS over TLS (RFC 7858).
const DoTPort = 853

// canary — канареечный домен Firefox. NXDOMAIN на него выключает DoH в браузере.
const canary = "use-application-dns.net"

// dohHosts — имена, за которыми живут публичные резолверы DoH.
//
// Список намеренно короткий: сюда попадают те, кого браузеры прописывают себе по умолчанию.
// Гнаться за полнотой бессмысленно — провайдеров сотни, а смысл не в том, чтобы закрыть все
// двери, а в том, чтобы браузер вернулся к системному резолверу.
var dohHosts = []string{
	// Google
	"dns.google",
	"dns64.dns.google",
	// Cloudflare — вместе с тем именем, под которым его прописывает Firefox
	"cloudflare-dns.com",
	"mozilla.cloudflare-dns.com",
	"one.one.one.one",
	"security.cloudflare-dns.com",
	"family.cloudflare-dns.com",
	// Quad9
	"dns.quad9.net",
	"dns9.quad9.net",
	"dns10.quad9.net",
	"dns11.quad9.net",
	// OpenDNS
	"doh.opendns.com",
	"doh.familyshield.opendns.com",
	// AdGuard
	"dns.adguard.com",
	"dns.adguard-dns.com",
	"dns-unfiltered.adguard.com",
	// NextDNS
	"dns.nextdns.io",
	// CleanBrowsing
	"doh.cleanbrowsing.org",
	// Прочие, встречающиеся в настройках браузеров
	"doh.pub",
	"dns.alidns.com",
	"doh.dns.sb",
	"dns.twnic.tw",
	"odvr.nic.cz",
}

// blocksDoH сообщает, нужно ли отказать этому имени ради перехвата DNS.
func blocksDoH(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return false
	}
	if name == canary || strings.HasSuffix(name, "."+canary) {
		return true
	}
	for _, host := range dohHosts {
		if name == host || strings.HasSuffix(name, "."+host) {
			return true
		}
	}
	return false
}
