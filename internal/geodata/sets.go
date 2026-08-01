package geodata

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Sets — загруженные базы. Реализует routing.Sets.
//
// Списки хранятся так, как ими пользуются: домены разложены по видам сравнения, подсети
// собраны по длине префикса. Самый частый случай — «домен и его поддомены» — решается
// поиском в карте, а не перебором: в `category-ads-all` десятки тысяч записей, и перебирать
// их на каждый поток нельзя.
type Sets struct {
	mu    sync.RWMutex
	sites map[string]*siteIndex
	ips   map[string]*ipIndex
}

type siteIndex struct {
	// root — домен и поддомены. Ключ — само имя.
	root map[string][]string
	// full — точное совпадение.
	full map[string][]string
	// plain — подстроки, перебираются подряд: их в списках немного.
	plain []attrValue
	// regex — выражения, тоже перебираются.
	regex []attrRegexp
}

type attrValue struct {
	value string
	attrs []string
}

type attrRegexp struct {
	re    *regexp.Regexp
	attrs []string
}

type ipIndex struct {
	v4 []netip.Prefix
	v6 []netip.Prefix
}

// New собирает пустой набор.
func New() *Sets {
	return &Sets{sites: make(map[string]*siteIndex), ips: make(map[string]*ipIndex)}
}

// LoadSites раскладывает разобранный geosite.dat.
func (s *Sets) LoadSites(sites []Site) {
	index := make(map[string]*siteIndex, len(sites))

	for _, site := range sites {
		idx := &siteIndex{root: make(map[string][]string), full: make(map[string][]string)}
		for _, d := range site.Domains {
			switch d.Kind {
			case DomainRoot:
				idx.root[d.Value] = mergeAttrs(idx.root[d.Value], d.Attrs)
			case DomainFull:
				idx.full[d.Value] = mergeAttrs(idx.full[d.Value], d.Attrs)
			case DomainPlain:
				idx.plain = append(idx.plain, attrValue{value: d.Value, attrs: d.Attrs})
			case DomainRegex:
				re, err := regexp.Compile(d.Value)
				if err != nil {
					// Негодное выражение в чужой базе — не повод ронять клиент.
					// Пропускаем именно эту запись, остальные работают.
					continue
				}
				idx.regex = append(idx.regex, attrRegexp{re: re, attrs: d.Attrs})
			}
		}
		index[site.Code] = idx
	}

	s.mu.Lock()
	s.sites = index
	s.mu.Unlock()
}

// LoadIPs раскладывает разобранный geoip.dat.
func (s *Sets) LoadIPs(sets []IPSet) {
	index := make(map[string]*ipIndex, len(sets))
	for _, set := range sets {
		idx := &ipIndex{}
		for _, p := range set.Prefixes {
			if p.Addr().Is4() {
				idx.v4 = append(idx.v4, p)
			} else {
				idx.v6 = append(idx.v6, p)
			}
		}
		index[set.Code] = idx
	}

	s.mu.Lock()
	s.ips = index
	s.mu.Unlock()
}

// Site сообщает, входит ли домен в список.
//
// Имя списка может нести пометку: `google@ads` означает «только записи гугла, помеченные
// как реклама». Так делят большие списки в наборах Loyalsoldier.
func (s *Sets) Site(list, domain string) bool {
	name, attr := splitAttr(list)

	s.mu.RLock()
	idx, ok := s.sites[name]
	s.mu.RUnlock()
	if !ok {
		return false
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if attrs, ok := idx.full[domain]; ok && hasAttr(attrs, attr) {
		return true
	}

	// Домен и поддомены: идём по точкам справа налево, отсекая по одной метке.
	// Для a.b.example.com это четыре поиска в карте вместо перебора всего списка.
	for name := domain; name != ""; {
		if attrs, ok := idx.root[name]; ok && hasAttr(attrs, attr) {
			return true
		}
		_, rest, found := strings.Cut(name, ".")
		if !found {
			break
		}
		name = rest
	}

	for _, p := range idx.plain {
		if strings.Contains(domain, p.value) && hasAttr(p.attrs, attr) {
			return true
		}
	}
	for _, r := range idx.regex {
		if r.re.MatchString(domain) && hasAttr(r.attrs, attr) {
			return true
		}
	}
	return false
}

// IP сообщает, входит ли адрес в список.
func (s *Sets) IP(list string, addr netip.Addr) bool {
	name, _ := splitAttr(list)

	s.mu.RLock()
	idx, ok := s.ips[name]
	s.mu.RUnlock()
	if !ok || !addr.IsValid() {
		return false
	}

	addr = addr.Unmap()
	prefixes := idx.v6
	if addr.Is4() {
		prefixes = idx.v4
	}
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// HasSite сообщает, известен ли список доменов.
func (s *Sets) HasSite(list string) bool {
	name, _ := splitAttr(list)
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.sites[name]
	return ok
}

// HasIP сообщает, известен ли список подсетей.
func (s *Sets) HasIP(list string) bool {
	name, _ := splitAttr(list)
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.ips[name]
	return ok
}

// SiteLists перечисляет имена списков доменов, по алфавиту.
//
// Имена отдаются как есть, без перевода и без объединения: их полторы тысячи, они приходят из
// чужой базы и меняются вместе с ней. Придумывать им человеческие названия значило бы
// пересобирать словарь на каждое обновление и врать там, где не угадал.
func (s *Sets) SiteLists() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortedKeys(s.sites)
}

// IPLists перечисляет имена списков подсетей, по алфавиту.
//
// Отдельно от списков доменов: это разные базы с разным смыслом, и смешивать их в один
// перечень — верный способ получить правило, которое ищет страну среди доменов.
func (s *Sets) IPLists() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortedKeys(s.ips)
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for name := range m {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Stats описывает загруженное — для строки в журнале и для панели.
func (s *Sets) Stats() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var domains, prefixes int
	for _, idx := range s.sites {
		domains += len(idx.root) + len(idx.full) + len(idx.plain) + len(idx.regex)
	}
	for _, idx := range s.ips {
		prefixes += len(idx.v4) + len(idx.v6)
	}
	return fmt.Sprintf("списков доменов %d (%d записей), списков подсетей %d (%d подсетей)",
		len(s.sites), domains, len(s.ips), prefixes)
}

// splitAttr разделяет `google@ads` на имя списка и пометку.
func splitAttr(list string) (name, attr string) {
	name, attr, _ = strings.Cut(strings.ToLower(list), "@")
	return name, attr
}

// hasAttr проверяет пометку. Пустая пометка подходит любой записи.
func hasAttr(attrs []string, want string) bool {
	if want == "" {
		return true
	}
	for _, a := range attrs {
		if a == want {
			return true
		}
	}
	return false
}

func mergeAttrs(existing, add []string) []string {
	if len(add) == 0 {
		// Запись без пометок подходит любому запросу с пометкой? Нет: пустой список
		// означает «пометок нет», и запрос с пометкой её не найдёт. Возвращаем как есть.
		return existing
	}
	return append(existing, add...)
}
