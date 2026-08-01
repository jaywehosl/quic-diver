package routing

import (
	"fmt"
	"log/slog"
	"sync"
)

// Decision — что делать с потоком и почему.
//
// Причина нужна не для красоты: человек, у которого сайт «вдруг пошёл не туда», должен
// увидеть, какое правило сработало, а не гадать.
type Decision struct {
	Action Action
	// Rule — номер сработавшего правила, начиная с единицы. Ноль означает, что не сработало
	// ни одно и решение приняло умолчание.
	Rule int
	// Reason — условие, которое совпало. Пустая строка у умолчания.
	Reason string
	// Force — сработало правило, помеченное «соблюдать всегда».
	Force bool
}

// ByDefault сообщает, что решение принято умолчанием, а не правилом.
func (d Decision) ByDefault() bool { return d.Rule == 0 }

func (d Decision) String() string {
	if d.ByDefault() {
		return string(d.Action) + " (по умолчанию)"
	}
	if d.Force {
		return fmt.Sprintf("%s (правило %d: %s, всегда)", d.Action, d.Rule, d.Reason)
	}
	return fmt.Sprintf("%s (правило %d: %s)", d.Action, d.Rule, d.Reason)
}

// rule — скомпилированное правило.
type rule struct {
	matchers []matcher
	action   Action
	comment  string
	force    bool
	// number — место в списке человека, начиная с единицы.
	//
	// Своё поле, а не позиция в срезе: выключенные правила в срез не попадают, и без этого
	// объяснение «правило 3» указывало бы на другую строку экрана.
	number int
}

// Engine принимает решения по потокам.
//
// Побеждает не первое совпавшее правило, а самое сильное: имя сильнее адреса, адрес сильнее
// процесса, а помеченное «соблюдать всегда» — сильнее всех. Внутри одной ступени решает
// порядок в списке, как в привычных списках. Почему именно так — в заголовке пакета.
type Engine struct {
	mu       sync.RWMutex
	rules    []rule
	fallback Action
	sets     Sets
	log      *slog.Logger
}

// New собирает движок.
//
// fallback — то самое умолчание из чекбокса: ActionEgress, если человек выбрал «через
// выходные узлы», иначе ActionDirect.
func New(rules []Rule, fallback Action, log *slog.Logger) (*Engine, error) {
	if !fallback.valid() || fallback == ActionBlock {
		// Умолчанием может быть только «куда идти», но не «никуда»: иначе клиент, забывший
		// правило, потерял бы вообще весь трафик.
		return nil, fmt.Errorf("routing: негодное умолчание %q", fallback)
	}
	if log == nil {
		log = slog.Default()
	}

	e := &Engine{fallback: fallback, log: log}
	if err := e.Replace(rules); err != nil {
		return nil, err
	}
	return e, nil
}

// Replace заменяет набор правил целиком.
//
// Целиком, а не по одному: половина старого набора рядом с половиной нового означала бы
// поведение, которого не задумывал никто.
func (e *Engine) Replace(rules []Rule) error {
	compiled := make([]rule, 0, len(rules))
	for i, r := range rules {
		action := Action(r.Action)
		if !action.valid() {
			return fmt.Errorf("routing: правило %d: неизвестное действие %q", i+1, r.Action)
		}
		if len(r.Match) == 0 {
			return fmt.Errorf("routing: правило %d: пустое условие", i+1)
		}
		// Выключенное проверяется наравне с прочими — негодное правило остаётся негодным,
		// сколько его ни выключай, — но в набор не попадает.
		if r.Off {
			for _, expr := range r.Match {
				if _, err := ParseMatcher(expr); err != nil {
					return fmt.Errorf("routing: правило %d: %w", i+1, err)
				}
			}
			continue
		}

		matchers := make([]matcher, 0, len(r.Match))
		for _, expr := range r.Match {
			m, err := ParseMatcher(expr)
			if err != nil {
				return fmt.Errorf("routing: правило %d: %w", i+1, err)
			}
			matchers = append(matchers, m)
		}
		compiled = append(compiled, rule{
			matchers: matchers,
			action:   action,
			comment:  r.Comment,
			force:    r.Force,
			number:   i + 1,
		})
	}

	e.mu.Lock()
	e.rules = compiled
	e.mu.Unlock()
	return nil
}

// SetSets подключает базы geosite и geoip. Ноль означает, что баз нет.
func (e *Engine) SetSets(sets Sets) {
	e.mu.Lock()
	e.sets = sets
	e.mu.Unlock()
}

// SetFallback меняет умолчание — это чекбокс, и он переключается на лету.
func (e *Engine) SetFallback(a Action) error {
	if !a.valid() || a == ActionBlock {
		return fmt.Errorf("routing: негодное умолчание %q", a)
	}
	e.mu.Lock()
	e.fallback = a
	e.mu.Unlock()
	return nil
}

// Fallback возвращает нынешнее умолчание.
func (e *Engine) Fallback() Action {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.fallback
}

// Decide решает судьбу потока.
//
// Условия внутри правила соединены «или»: geosite:ru и geoip:ru в одном правиле означают
// «российское по имени ИЛИ по адресу». Так и нужно — имя известно не всегда, и правило,
// требующее совпадения обоих, молча промахивалось бы там, где домен неизвестен.
//
// Побеждает не первое совпавшее, а самое сильное: ступень условия важнее места в списке.
// Поэтому перебираются все правила до конца — выйти на первом совпадении нельзя, дальше
// может найтись правило по имени, а нашлось пока только по процессу.
func (e *Engine) Decide(f Flow) Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	best := Decision{Action: e.fallback}
	bestClass := classNone

	for _, r := range e.rules {
		for _, m := range r.matchers {
			if !m.match(f, e.sets) {
				continue
			}
			c := m.class()
			if r.force {
				c = classForce
			}
			// Строго меньше: при равной ступени остаётся тот, кого нашли раньше, — то есть
			// побеждает более раннее правило списка.
			if c >= bestClass {
				continue
			}
			bestClass = c
			best = Decision{Action: r.action, Rule: r.number, Reason: m.String(), Force: r.force}
		}
	}
	return best
}

// NeedsAddr сообщает, есть ли правила, которым нужен настоящий адрес назначения.
//
// В туннеле имя разрешается подменным адресом, и настоящий клиенту неизвестен: он шлёт узлу
// имя, а тот разрешает его сам. Узнать настоящий адрес можно, но это лишний поход к резолверу
// на каждое новое имя — платить за него стоит только там, где он на что-то влияет.
//
// Влияет он на условия по адресу: `geoip:` и `ip:`. Правила по именам и процессам обходятся
// тем, что известно и так.
func (e *Engine) NeedsAddr() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, r := range e.rules {
		for _, m := range r.matchers {
			switch m.(type) {
			case geoipMatcher, cidrMatcher:
				return true
			}
		}
	}
	return false
}

// Inactive перечисляет условия, которые не работают без баз.
//
// Нужно, чтобы сказать человеку правду: правила с geosite и geoip при незагруженных базах
// не срабатывают никогда, и молчать об этом нельзя — он будет считать, что реклама режется,
// а она не режется.
func (e *Engine) Inactive() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var out []string
	for _, r := range e.rules {
		for _, m := range r.matchers {
			if !m.needsSets() {
				continue
			}
			if e.sets != nil && known(e.sets, m) {
				continue
			}
			out = append(out, fmt.Sprintf("правило %d: %s", r.number, m))
		}
	}
	return out
}

// InactiveRules перечисляет номера правил, которые не работают без баз, начиная с единицы.
//
// То же, что Inactive, но пригодное к сопоставлению: Inactive отдаёт текст для журнала, а
// экрану правил нужно пометить конкретные строки списка, и разбирать этот текст обратно —
// худшее из возможных решений.
func (e *Engine) InactiveRules() []int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var out []int
	for _, r := range e.rules {
		for _, m := range r.matchers {
			if !m.needsSets() {
				continue
			}
			if e.sets != nil && known(e.sets, m) {
				continue
			}
			out = append(out, r.number)
			break
		}
	}
	return out
}

// known сообщает, есть ли в базах список, на который ссылается условие.
func known(sets Sets, m matcher) bool {
	switch v := m.(type) {
	case geositeMatcher:
		return sets.HasSite(v.list)
	case geoipMatcher:
		return sets.HasIP(v.list)
	default:
		return true
	}
}

// Len возвращает число правил.
func (e *Engine) Len() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}
