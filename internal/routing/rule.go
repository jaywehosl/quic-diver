// Package routing решает судьбу каждого потока.
//
// Правило имеет ровно три исхода: выпустить наружу на том узле, к которому подключён клиент
// (`direct`), отправить через выходной узел (`egress`) или оборвать (`block`). Никаких
// параметров у исходов нет — какой именно выходной узел достанется потоку, решает гонка.
//
// # Флаг клиента и правила
//
// Чекбокс «через выходные узлы» задаёт умолчание для всего, что не подошло ни под одно
// правило. Правила его переопределяют, каждое для себя. Работает так: выбран чекбокс, а для
// yandex.ru стоит `direct` — значит весь трафик идёт клиент→вход→выход→интернет, а яндекс
// клиент→вход→интернет.
//
// # Кто кого перебивает
//
// Порядок в списке решает не всё. Правило по имени всегда сильнее правила по процессу, и это
// не тонкость реализации, а то, чего человек ждёт:
//
//	process:chrome.exe → egress
//	domain:yandex.ru   → direct
//
// Яндекс, открытый в хроме, обязан пойти через входной узел. Иначе «через выход весь хром»
// означало бы «и яндекс тоже», а человек только что написал обратное — и написал он это
// про конкретное имя, а не про целую программу.
//
// Отсюда три ступени, от сильной к слабой: имя, адрес, процесс. Внутри ступени побеждает
// первое совпавшее правило — как в привычных списках.
//
// Поверх всего — флаг «соблюдать всегда» (Force). Правило с ним не перебивается ничем: так
// человек говорит «вот это — без исключений», не выясняя, какая ступень сильнее.
package routing

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Action — что делать с потоком.
type Action string

const (
	// ActionDirect — наружу на том узле, к которому подключён клиент.
	ActionDirect Action = "direct"
	// ActionEgress — через выходной узел.
	ActionEgress Action = "egress"
	// ActionBlock — оборвать: RST для потока, NXDOMAIN на этапе имени.
	ActionBlock Action = "block"
)

func (a Action) valid() bool {
	switch a {
	case ActionDirect, ActionEgress, ActionBlock:
		return true
	default:
		return false
	}
}

// Flow — то, что известно о потоке к моменту решения.
//
// Домен известен не всегда: он берётся из перехваченного DNS-запроса или из подменного
// адреса. Когда его нет, работают признаки, которые есть всегда, — адрес и порт. Поэтому
// правило, важное для человека, стоит задавать и по домену, и по подсети: домен точнее,
// адрес надёжнее.
type Flow struct {
	// Domain — имя, если его удалось узнать.
	Domain string
	// Addr — адрес назначения.
	Addr netip.Addr
	// Port — порт назначения.
	Port uint16
	// Process — имя процесса, если клиент умеет его определять.
	Process string
}

// Sets — базы geosite и geoip. Пустой означает, что базы не загружены.
//
// Отдельный интерфейс нужен затем, что без баз клиент обязан работать: правила по доменам,
// подсетям и процессам от них не зависят вовсе.
type Sets interface {
	// Site сообщает, входит ли домен в список.
	Site(list, domain string) bool
	// IP сообщает, входит ли адрес в список.
	IP(list string, addr netip.Addr) bool
	// HasSite сообщает, известен ли такой список доменов.
	HasSite(list string) bool
	// HasIP сообщает, известен ли такой список адресов.
	HasIP(list string) bool
}

// Rule — одно правило маршрутизации.
//
// Правила задаёт человек у себя на устройстве: ТЗ говорит «поддержка формата v2fly на
// клиенте. Выбрал geosite:… — отправил в blackhole». Сеть их не назначает и назначать не
// может — применяет-то их всё равно клиент.
type Rule struct {
	// Match — условия. Совпало любое — правило сработало.
	Match []string `json:"match"`
	// Action — что делать: direct, egress или block.
	Action string `json:"action"`
	// Comment — заметка человека. На решение не влияет.
	Comment string `json:"comment,omitempty"`
	// Force — соблюдать всегда: правило не перебивается никаким другим.
	//
	// Нужно затем, что ступени приоритета покрывают обычные случаи, но не все. Человек,
	// которому нужно «этот процесс — только через выход, что бы там ни было написано про
	// домены», говорит это одним флагом, а не перестройкой всего списка.
	Force bool `json:"force,omitempty"`
	// Off — правило выключено: остаётся в списке, но ни на что не влияет.
	//
	// Выключить, а не удалить, — потому что правила пишут один раз и надолго. Проверить
	// «а если без него», отключив на минуту, человек должен уметь без того, чтобы набирать
	// потом всё заново.
	Off bool `json:"off,omitempty"`
}

// class — ступень приоритета условия.
//
// Меньше — сильнее. Порядок задан не вкусом: имя — самое точное, что известно о потоке;
// адрес известен всегда, но говорит меньше; процесс не про место назначения вовсе.
type class int

const (
	// classForce — правило, помеченное «соблюдать всегда».
	classForce class = iota
	// classDomain — условие по имени.
	classDomain
	// classAddr — условие по адресу, подсети или порту.
	classAddr
	// classProcess — условие по имени процесса.
	classProcess
	// classNone — ничего не совпало.
	classNone
)

// matcher — одно условие правила.
type matcher interface {
	match(f Flow, sets Sets) bool
	// needsSets сообщает, что условие бесполезно без баз.
	needsSets() bool
	// class — ступень приоритета этого условия.
	class() class
	String() string
}

// ParseMatcher разбирает условие в формате v2fly.
//
// Поддерживаются те же префиксы, к которым привыкли пользователи списков Loyalsoldier:
//
//	domain:example.com   домен и все поддомены
//	full:example.com     точное совпадение
//	keyword:goog         подстрока в имени
//	regexp:^ads\.        регулярное выражение
//	geosite:google       список доменов из базы
//	geoip:ru             список подсетей из базы
//	ip:10.0.0.0/8        подсеть
//	port:443             порт
//	process:chrome.exe   имя процесса
//
// Условие без префикса считается доменом: так короче и так же поступают привычные списки.
func ParseMatcher(s string) (matcher, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("routing: пустое условие")
	}

	kind, value, found := strings.Cut(s, ":")
	if !found {
		return domainMatcher{suffix: strings.ToLower(s)}, nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("routing: условие %q без значения", s)
	}

	switch strings.ToLower(kind) {
	case "domain", "suffix":
		return domainMatcher{suffix: strings.ToLower(value)}, nil
	case "full":
		return fullMatcher{name: strings.ToLower(value)}, nil
	case "keyword":
		return keywordMatcher{word: strings.ToLower(value)}, nil
	case "regexp":
		re, err := regexp.Compile(value)
		if err != nil {
			return nil, fmt.Errorf("routing: выражение %q: %w", value, err)
		}
		return regexpMatcher{re: re}, nil
	case "geosite":
		return geositeMatcher{list: strings.ToLower(value)}, nil
	case "geoip":
		return geoipMatcher{list: strings.ToLower(value)}, nil
	case "ip", "cidr":
		prefix, err := parsePrefix(value)
		if err != nil {
			return nil, err
		}
		return cidrMatcher{prefix: prefix}, nil
	case "port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("routing: порт %q: %w", value, err)
		}
		return portMatcher{port: uint16(port)}, nil
	case "process":
		return processMatcher{name: strings.ToLower(value)}, nil
	default:
		return nil, fmt.Errorf("routing: неизвестный вид условия %q", kind)
	}
}

// parsePrefix понимает и подсеть, и одиночный адрес.
func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("routing: адрес или подсеть %q: %w", s, err)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// domainMatcher — домен и его поддомены.
type domainMatcher struct{ suffix string }

func (m domainMatcher) match(f Flow, _ Sets) bool {
	d := strings.ToLower(f.Domain)
	if d == "" {
		return false
	}
	if d == m.suffix {
		return true
	}
	// Именно точка, а не просто окончание строки: иначе правило для "example.com"
	// поймало бы "notexample.com", то есть чужой сайт.
	return strings.HasSuffix(d, "."+m.suffix)
}

func (m domainMatcher) needsSets() bool { return false }
func (m domainMatcher) class() class    { return classDomain }
func (m domainMatcher) String() string  { return "domain:" + m.suffix }

// fullMatcher — точное имя.
type fullMatcher struct{ name string }

func (m fullMatcher) match(f Flow, _ Sets) bool { return strings.ToLower(f.Domain) == m.name }
func (m fullMatcher) needsSets() bool           { return false }
func (m fullMatcher) class() class              { return classDomain }
func (m fullMatcher) String() string            { return "full:" + m.name }

// keywordMatcher — подстрока в имени.
type keywordMatcher struct{ word string }

func (m keywordMatcher) match(f Flow, _ Sets) bool {
	return f.Domain != "" && strings.Contains(strings.ToLower(f.Domain), m.word)
}
func (m keywordMatcher) needsSets() bool { return false }
func (m keywordMatcher) class() class    { return classDomain }
func (m keywordMatcher) String() string  { return "keyword:" + m.word }

// regexpMatcher — регулярное выражение по имени.
type regexpMatcher struct{ re *regexp.Regexp }

func (m regexpMatcher) match(f Flow, _ Sets) bool {
	return f.Domain != "" && m.re.MatchString(strings.ToLower(f.Domain))
}
func (m regexpMatcher) needsSets() bool { return false }
func (m regexpMatcher) class() class    { return classDomain }
func (m regexpMatcher) String() string  { return "regexp:" + m.re.String() }

// geositeMatcher — список доменов из базы.
type geositeMatcher struct{ list string }

func (m geositeMatcher) match(f Flow, sets Sets) bool {
	if sets == nil || f.Domain == "" {
		return false
	}
	return sets.Site(m.list, strings.ToLower(f.Domain))
}
func (m geositeMatcher) needsSets() bool { return true }
func (m geositeMatcher) class() class    { return classDomain }
func (m geositeMatcher) String() string  { return "geosite:" + m.list }

// geoipMatcher — список подсетей из базы.
type geoipMatcher struct{ list string }

func (m geoipMatcher) match(f Flow, sets Sets) bool {
	if sets == nil || !f.Addr.IsValid() {
		return false
	}
	return sets.IP(m.list, f.Addr)
}
func (m geoipMatcher) needsSets() bool { return true }
func (m geoipMatcher) class() class    { return classAddr }
func (m geoipMatcher) String() string  { return "geoip:" + m.list }

// cidrMatcher — подсеть.
type cidrMatcher struct{ prefix netip.Prefix }

func (m cidrMatcher) match(f Flow, _ Sets) bool {
	return f.Addr.IsValid() && m.prefix.Contains(f.Addr.Unmap())
}
func (m cidrMatcher) needsSets() bool { return false }
func (m cidrMatcher) class() class    { return classAddr }
func (m cidrMatcher) String() string  { return "ip:" + m.prefix.String() }

// portMatcher — порт назначения.
type portMatcher struct{ port uint16 }

func (m portMatcher) match(f Flow, _ Sets) bool { return f.Port == m.port }
func (m portMatcher) needsSets() bool           { return false }
func (m portMatcher) class() class              { return classAddr }
func (m portMatcher) String() string            { return "port:" + strconv.Itoa(int(m.port)) }

// processMatcher — имя процесса.
type processMatcher struct{ name string }

func (m processMatcher) match(f Flow, _ Sets) bool {
	return f.Process != "" && strings.ToLower(f.Process) == m.name
}
func (m processMatcher) needsSets() bool { return false }
func (m processMatcher) class() class    { return classProcess }
func (m processMatcher) String() string  { return "process:" + m.name }
