package oplog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"
)

// Fingerprint — отпечаток генезис-записи, он же имя сети.
//
// Лежит в конфиге каждого узла и заносится туда руками при установке. Доверие к журналу
// берётся именно отсюда: подпись говорит лишь «эту запись сделал владелец такого-то ключа»,
// а вот что этот ключ — наш, знает только отпечаток.
type Fingerprint [32]byte

func (f Fingerprint) String() string { return hex.EncodeToString(f[:]) }

func (f Fingerprint) IsZero() bool { return f == Fingerprint{} }

// MarshalJSON пишет отпечаток строкой, а не массивом из тридцати двух чисел.
//
// Разница не только в длине: отпечаток человек сверяет глазами, и в конфиге, и в бандле он
// обязан выглядеть так же, как в выводе `qd-admin list`.
func (f Fingerprint) MarshalJSON() ([]byte, error) { return json.Marshal(f.String()) }

func (f *Fingerprint) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := ParseFingerprint(s)
	if err != nil {
		return err
	}
	*f = parsed
	return nil
}

// ParseFingerprint разбирает шестнадцатеричную запись отпечатка.
func ParseFingerprint(s string) (Fingerprint, error) {
	var f Fingerprint
	b, err := hex.DecodeString(s)
	if err != nil {
		return f, fmt.Errorf("oplog: разбор отпечатка сети: %w", err)
	}
	if len(b) != len(f) {
		return f, fmt.Errorf("oplog: отпечаток сети должен быть %d байт, получено %d", len(f), len(b))
	}
	copy(f[:], b)
	return f, nil
}

// FingerprintOf считает отпечаток записи целиком, вместе с подписью.
func FingerprintOf(o *Op) (Fingerprint, error) {
	raw, err := o.Bytes()
	if err != nil {
		return Fingerprint{}, err
	}
	return Fingerprint(sha256.Sum256(raw)), nil
}

// Effect — что State сделал с записью.
type Effect uint8

const (
	// EffectApplied — запись изменила состояние.
	EffectApplied Effect = iota
	// EffectSuperseded — законная запись, но объект уже правили позже. Хранить обязательно:
	// сосед, у которого более поздней правки ещё нет, получит её от нас.
	EffectSuperseded
	// EffectUnknown — вид операции этой версии неизвестен. Хранить и пересылать, не применять.
	EffectUnknown
)

func (e Effect) String() string {
	switch e {
	case EffectApplied:
		return "applied"
	case EffectSuperseded:
		return "superseded"
	case EffectUnknown:
		return "unknown"
	default:
		return fmt.Sprintf("effect(%d)", uint8(e))
	}
}

var (
	ErrNoGenesis     = errors.New("oplog: первой записью должен быть генезис")
	ErrDoubleGenesis = errors.New("oplog: генезис уже был")
	ErrForeignNet    = errors.New("oplog: генезис от другой сети")
	ErrUnknownKey    = errors.New("oplog: запись подписана неизвестным ключом")
	ErrRevokedKey    = errors.New("oplog: запись подписана отозванным ключом")
	ErrForbidden     = errors.New("oplog: у ключа недостаточно прав для этой операции")
	ErrGap           = errors.New("oplog: в последовательности ключа пропуск")
	ErrReplay        = errors.New("oplog: запись с таким счётчиком уже применялась")
	ErrLastOwner     = errors.New("oplog: нельзя отозвать последнего владельца")
	ErrNoSuchObject  = errors.New("oplog: правка объекта, которого нет")
)

// stamp — чем разрешается конфликт двух правок одного объекта.
type stamp struct {
	at  time.Time
	key KeyID
}

// newer сообщает, свежее ли s, чем other. При совпадении времени сравниваем идентификаторы
// ключей — не потому что один админ важнее, а чтобы у всех узлов вышел одинаковый ответ.
func (s stamp) newer(other stamp) bool {
	if !s.at.Equal(other.at) {
		return s.at.After(other.at)
	}
	return string(s.key[:]) > string(other.key[:])
}

// State — состояние сети, собранное из журнала.
//
// State ничего не хранит на диске и не знает про сеть: это чистая функция от последовательности
// записей. Благодаря этому одинаковый журнал даёт одинаковое состояние на любом узле, а
// проверить логику можно без базы, узлов и сокетов.
type State struct {
	network  string
	genesis  Fingerprint
	admins   map[KeyID]AdminKey
	revoked  map[KeyID]struct{}
	clients  map[string]Client
	nodes    map[string]Node
	routing  Routing
	settings Settings

	counters map[KeyID]uint64
	stamps   map[string]stamp
}

// NewState создаёт пустое состояние, ждущее генезиса.
func NewState() *State {
	return &State{
		admins:   make(map[KeyID]AdminKey),
		revoked:  make(map[KeyID]struct{}),
		clients:  make(map[string]Client),
		nodes:    make(map[string]Node),
		counters: make(map[KeyID]uint64),
		stamps:   make(map[string]stamp),
	}
}

// Network возвращает имя сети из генезиса.
func (s *State) Network() string { return s.network }

// Genesis возвращает отпечаток сети.
func (s *State) Genesis() Fingerprint { return s.genesis }

// Client отдаёт клиента по идентификатору.
func (s *State) Client(id string) (Client, bool) { c, ok := s.clients[id]; return c, ok }

// Node отдаёт узел по идентификатору.
func (s *State) Node(id string) (Node, bool) { n, ok := s.nodes[id]; return n, ok }

// Clients перечисляет клиентов, отсортированных по идентификатору.
func (s *State) Clients() []Client {
	return sortedByID(s.clients, func(c Client) string { return c.ID })
}

// Nodes перечисляет узлы, отсортированные по идентификатору.
func (s *State) Nodes() []Node { return sortedByID(s.nodes, func(n Node) string { return n.ID }) }

// NodesWithRole перечисляет узлы указанной роли.
func (s *State) NodesWithRole(role string) []Node {
	var out []Node
	for _, n := range s.Nodes() {
		if n.HasRole(role) {
			out = append(out, n)
		}
	}
	return out
}

// Admins перечисляет действующие ключи администраторов, отсортированные по идентификатору.
func (s *State) Admins() []AdminKey {
	out := slices.Collect(maps.Values(s.admins))
	slices.SortFunc(out, func(a, b AdminKey) int {
		x, y := a.ID(), b.ID()
		return slices.Compare(x[:], y[:])
	})
	return out
}

// AdminKey отдаёт действующий ключ администратора.
func (s *State) AdminKey(id KeyID) (AdminKey, bool) { a, ok := s.admins[id]; return a, ok }

// IsRevoked сообщает, отозван ли ключ.
func (s *State) IsRevoked(id KeyID) bool { _, ok := s.revoked[id]; return ok }

// Routing возвращает действующие правила маршрутизации.
func (s *State) Routing() Routing { return s.routing }

// Settings возвращает действующие параметры сети.
func (s *State) Settings() Settings { return s.settings }

// Counter возвращает последний применённый счётчик ключа — с него сосед понимает,
// чего ему недостаёт.
func (s *State) Counter(key KeyID) uint64 { return s.counters[key] }

// Counters отдаёт копию всех счётчиков: это и есть «где я нахожусь» при обмене журналами.
func (s *State) Counters() map[KeyID]uint64 { return maps.Clone(s.counters) }

func sortedByID[T any](m map[string]T, id func(T) string) []T {
	out := slices.Collect(maps.Values(m))
	slices.SortFunc(out, func(a, b T) int {
		if id(a) < id(b) {
			return -1
		}
		if id(a) > id(b) {
			return 1
		}
		return 0
	})
	return out
}

// Apply проверяет и применяет одну запись.
//
// Порядок проверок важен: сперва подлинность (подпись и ключ), затем место в
// последовательности, и только потом смысл. Запись, не прошедшую подлинность, нельзя даже
// сохранять — иначе кто угодно набьёт узлу базу мусором.
func (s *State) Apply(op *Op) (Effect, error) {
	if s.genesis.IsZero() {
		return 0, s.applyGenesis(op)
	}
	if op.Kind == KindGenesis {
		return 0, ErrDoubleGenesis
	}

	key, err := s.authorize(op)
	if err != nil {
		return 0, err
	}
	if err := s.checkSequence(op); err != nil {
		return 0, err
	}

	if !op.Kind.Known() {
		// Запись из будущего: подпись сошлась, прав хватает, смысл неизвестен. Двигаем
		// счётчик, чтобы следующие записи этого ключа не считались пришедшими с пропуском,
		// и оставляем применение более новой версии узла.
		s.counters[op.Key] = op.Counter
		return EffectUnknown, nil
	}

	payload, err := DecodePayload(op)
	if err != nil {
		return 0, err
	}
	if key.Scope < op.Kind.RequiredScope() {
		return 0, fmt.Errorf("%w: %s требует %s, у ключа %s", ErrForbidden, op.Kind, op.Kind.RequiredScope(), key.Scope)
	}

	effect, err := s.mutate(op, payload)
	if err != nil {
		return 0, err
	}
	s.counters[op.Key] = op.Counter
	return effect, nil
}

// applyGenesis принимает первую запись сети.
func (s *State) applyGenesis(op *Op) error {
	if op.Kind != KindGenesis {
		return ErrNoGenesis
	}
	payload, err := DecodePayload(op)
	if err != nil {
		return err
	}
	g := payload.(*Genesis)

	// Генезис подписывается одним из перечисленных в нём же владельцев. Само по себе это
	// ничего не доказывает — доверие даёт отпечаток из конфига, — но защищает от записи,
	// сделанной ключом, которого в сети нет вовсе.
	var signer *AdminKey
	for i := range g.Owners {
		if g.Owners[i].ID() == op.Key {
			signer = &g.Owners[i]
			break
		}
	}
	if signer == nil {
		return fmt.Errorf("%w: подписант %s не значится среди владельцев", ErrUnknownKey, op.Key)
	}
	if err := op.Verify(ed25519.PublicKey(signer.PublicKey)); err != nil {
		return err
	}
	if op.Counter != 1 {
		return fmt.Errorf("%w: счётчик генезиса должен быть 1, получено %d", ErrGap, op.Counter)
	}

	fp, err := FingerprintOf(op)
	if err != nil {
		return err
	}
	s.network = g.Network
	s.genesis = fp
	for _, o := range g.Owners {
		s.admins[o.ID()] = o
	}
	s.counters[op.Key] = op.Counter
	return nil
}

// authorize проверяет подпись и то, что ключ вправе что-то делать.
func (s *State) authorize(op *Op) (AdminKey, error) {
	if _, gone := s.revoked[op.Key]; gone {
		// Отзыв бьёт по всем ещё не применённым записям ключа, включая помеченные задним
		// числом. Иначе укравший ключ ставил бы в записи прошедшее время и обходил отзыв.
		return AdminKey{}, fmt.Errorf("%w: %s", ErrRevokedKey, op.Key)
	}
	key, ok := s.admins[op.Key]
	if !ok {
		return AdminKey{}, fmt.Errorf("%w: %s", ErrUnknownKey, op.Key)
	}
	if err := op.Verify(ed25519.PublicKey(key.PublicKey)); err != nil {
		return AdminKey{}, err
	}
	return key, nil
}

// checkSequence следит за тем, что записи ключа идут подряд.
//
// Пропуск — не ошибка данных, а сообщение: «мы получили не всё». Журнал разносится между
// узлами, и молча применить запись через дырку значило бы собрать состояние, которого ни у
// кого нет.
func (s *State) checkSequence(op *Op) error {
	last := s.counters[op.Key]
	switch {
	case op.Counter <= last:
		return fmt.Errorf("%w: ключ %s, счётчик %d, уже применён %d", ErrReplay, op.Key, op.Counter, last)
	case op.Counter > last+1:
		return fmt.Errorf("%w: ключ %s, ждали %d, получили %d", ErrGap, op.Key, last+1, op.Counter)
	}
	return nil
}

// mutate меняет состояние. К этому моменту запись уже подлинна, законна и понятна.
func (s *State) mutate(op *Op, payload any) (Effect, error) {
	st := stamp{at: op.Time, key: op.Key}

	switch p := payload.(type) {
	case *AdminAdd:
		return s.write("admin/"+p.Key.ID().String(), st, func() error {
			delete(s.revoked, p.Key.ID())
			s.admins[p.Key.ID()] = p.Key
			return nil
		})

	case *AdminRevoke:
		return s.write("admin/"+p.KeyID.String(), st, func() error {
			if _, ok := s.admins[p.KeyID]; !ok {
				return fmt.Errorf("%w: ключ %s", ErrNoSuchObject, p.KeyID)
			}
			if s.ownersLeftWithout(p.KeyID) == 0 {
				return ErrLastOwner
			}
			delete(s.admins, p.KeyID)
			s.revoked[p.KeyID] = struct{}{}
			return nil
		})

	case *Client:
		return s.write("client/"+p.ID, st, func() error {
			if op.Kind == KindClientUpdate {
				if _, ok := s.clients[p.ID]; !ok {
					return fmt.Errorf("%w: клиент %s", ErrNoSuchObject, p.ID)
				}
			}
			s.clients[p.ID] = *p
			return nil
		})

	case *ClientRevoke:
		return s.write("client/"+p.ID, st, func() error {
			if _, ok := s.clients[p.ID]; !ok {
				return fmt.Errorf("%w: клиент %s", ErrNoSuchObject, p.ID)
			}
			delete(s.clients, p.ID)
			return nil
		})

	case *Node:
		return s.write("node/"+p.ID, st, func() error {
			if op.Kind == KindNodeUpdate {
				if _, ok := s.nodes[p.ID]; !ok {
					return fmt.Errorf("%w: узел %s", ErrNoSuchObject, p.ID)
				}
			}
			s.nodes[p.ID] = *p
			return nil
		})

	case *NodeRevoke:
		return s.write("node/"+p.ID, st, func() error {
			if _, ok := s.nodes[p.ID]; !ok {
				return fmt.Errorf("%w: узел %s", ErrNoSuchObject, p.ID)
			}
			delete(s.nodes, p.ID)
			return nil
		})

	case *Routing:
		return s.write("routing", st, func() error { s.routing = *p; return nil })

	case *Settings:
		return s.write("settings", st, func() error { s.settings = *p; return nil })

	default:
		return 0, fmt.Errorf("oplog: применять %T нечем", payload)
	}
}

// write применяет изменение объекта, если наша правка свежее последней.
//
// Это last-writer-wins по паре (время, ключ). Правки разных админов приходят в произвольном
// порядке — у каждого своя последовательность, — поэтому «пришло позже» и «сделано позже» это
// разные вещи, и решать должно второе.
func (s *State) write(object string, st stamp, apply func() error) (Effect, error) {
	if prev, ok := s.stamps[object]; ok && !st.newer(prev) {
		return EffectSuperseded, nil
	}
	if err := apply(); err != nil {
		return 0, err
	}
	s.stamps[object] = st
	return EffectApplied, nil
}

// ownersLeftWithout считает, сколько владельцев останется без указанного ключа.
func (s *State) ownersLeftWithout(id KeyID) int {
	n := 0
	for k, a := range s.admins {
		if k != id && a.Scope == ScopeOwner {
			n++
		}
	}
	return n
}
