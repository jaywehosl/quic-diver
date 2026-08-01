package oplog

import (
	"errors"
	"testing"
	"time"
)

// network поднимает сеть с двумя владельцами и отдаёт состояние вместе с их подписантами.
type network struct {
	t         *testing.T
	state     *State
	owners    [2]*MemorySigner
	counter   map[KeyID]uint64
	clock     time.Time
	genesisOp *Op
}

func newNetwork(t *testing.T) *network {
	t.Helper()
	n := &network{
		t:       t,
		state:   NewState(),
		owners:  [2]*MemorySigner{mustSigner(t), mustSigner(t)},
		counter: make(map[KeyID]uint64),
		clock:   time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
	}
	g := Genesis{
		Network: "qdiver",
		Owners: []AdminKey{
			{PublicKey: PublicKey(n.owners[0].Public()), Scope: ScopeOwner, Label: "основной"},
			{PublicKey: PublicKey(n.owners[1].Public()), Scope: ScopeOwner, Label: "запасной"},
		},
	}
	n.genesisOp = n.sign(n.owners[0], KindGenesis, g)
	if _, err := n.state.Apply(n.genesisOp); err != nil {
		t.Fatalf("генезис: %v", err)
	}
	return n
}

// tick сдвигает часы, чтобы у записей было разное время.
func (n *network) tick() time.Time {
	n.clock = n.clock.Add(time.Second)
	return n.clock
}

// sign собирает подписанную запись, ведя счётчик за подписанта.
func (n *network) sign(s *MemorySigner, kind Kind, payload any) *Op {
	n.t.Helper()
	id := s.KeyID()
	n.counter[id]++
	op, err := NewOp(s, kind, n.counter[id], n.tick(), payload)
	if err != nil {
		n.t.Fatalf("сборка %s: %v", kind, err)
	}
	return op
}

func (n *network) apply(s *MemorySigner, kind Kind, payload any) (Effect, error) {
	n.t.Helper()
	return n.state.Apply(n.sign(s, kind, payload))
}

func (n *network) client(id string) Client {
	n.t.Helper()
	return Client{ID: id, PublicKey: testPubKey(n.t), Limits: Limits{Devices: 2}}
}

func TestGenesisMustComeFirst(t *testing.T) {
	s := NewState()
	signer := mustSigner(t)
	op, err := NewOp(signer, KindClientAdd, 1, time.Now(), Client{ID: "vasya", PublicKey: testPubKey(t)})
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	if _, err := s.Apply(op); !errors.Is(err, ErrNoGenesis) {
		t.Fatalf("состояние без генезиса приняло операцию: %v", err)
	}
}

func TestGenesisSignerMustBeAnOwner(t *testing.T) {
	s := NewState()
	outsider := mustSigner(t)
	g := Genesis{
		Network: "qdiver",
		Owners: []AdminKey{
			{PublicKey: testPubKey(t), Scope: ScopeOwner},
			{PublicKey: testPubKey(t), Scope: ScopeOwner},
		},
	}
	op, err := NewOp(outsider, KindGenesis, 1, time.Now(), g)
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	if _, err := s.Apply(op); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("генезис от постороннего принят: %v", err)
	}
}

func TestGenesisFingerprintIsStable(t *testing.T) {
	n := newNetwork(t)
	if n.state.Genesis().IsZero() {
		t.Fatal("отпечаток сети не посчитан")
	}
	if n.state.Network() != "qdiver" {
		t.Fatalf("имя сети: %q", n.state.Network())
	}
	parsed, err := ParseFingerprint(n.state.Genesis().String())
	if err != nil {
		t.Fatalf("разбор отпечатка: %v", err)
	}
	if parsed != n.state.Genesis() {
		t.Fatal("отпечаток не пережил round-trip")
	}
}

func TestSecondGenesisRejected(t *testing.T) {
	n := newNetwork(t)
	g := Genesis{
		Network: "чужая",
		Owners: []AdminKey{
			{PublicKey: PublicKey(n.owners[0].Public()), Scope: ScopeOwner},
			{PublicKey: testPubKey(t), Scope: ScopeOwner},
		},
	}
	if _, err := n.apply(n.owners[0], KindGenesis, g); !errors.Is(err, ErrDoubleGenesis) {
		t.Fatalf("второй генезис принят: %v", err)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	n := newNetwork(t)
	outsider := mustSigner(t)
	if _, err := n.apply(outsider, KindClientAdd, n.client("vasya")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("операция от постороннего ключа принята: %v", err)
	}
}

func TestOperatorCannotTouchNodes(t *testing.T) {
	n := newNetwork(t)
	bot := mustSigner(t)
	if _, err := n.apply(n.owners[0], KindAdminAdd, AdminAdd{Key: AdminKey{
		PublicKey: PublicKey(bot.Public()), Scope: ScopeOperator, Label: "бот",
	}}); err != nil {
		t.Fatalf("выдача прав оператору: %v", err)
	}

	// Клиентов оператору можно.
	if eff, err := n.apply(bot, KindClientAdd, n.client("vasya")); err != nil || eff != EffectApplied {
		t.Fatalf("оператор не смог завести клиента: %v (%s)", err, eff)
	}

	// Узлы — нет.
	node := Node{
		ID: "warsaw", PublicKey: testPubKey(t), Roles: []string{RoleEgress},
		Domain: "a.example.com", Endpoints: []string{"1.2.3.4:443"},
	}
	if _, err := n.apply(bot, KindNodeAdd, node); !errors.Is(err, ErrForbidden) {
		t.Fatalf("оператор добавил узел: %v", err)
	}
}

// Отзыв обязан бить и по записям, помеченным задним числом: иначе укравший ключ поставит
// в них прошедшее время и продолжит работать.
func TestRevokedKeyCannotBackdateOperations(t *testing.T) {
	n := newNetwork(t)
	bot := mustSigner(t)
	if _, err := n.apply(n.owners[0], KindAdminAdd, AdminAdd{Key: AdminKey{
		PublicKey: PublicKey(bot.Public()), Scope: ScopeOperator,
	}}); err != nil {
		t.Fatalf("выдача прав: %v", err)
	}

	// Вор заранее заготовил запись, помеченную прошлым временем.
	backdated, err := NewOp(bot, KindClientAdd, 1, n.clock.Add(-time.Hour), n.client("thief"))
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}

	if _, err := n.apply(n.owners[0], KindAdminRevoke, AdminRevoke{KeyID: bot.KeyID()}); err != nil {
		t.Fatalf("отзыв: %v", err)
	}
	if _, err := n.state.Apply(backdated); !errors.Is(err, ErrRevokedKey) {
		t.Fatalf("запись отозванного ключа задним числом принята: %v", err)
	}
	if !n.state.IsRevoked(bot.KeyID()) {
		t.Fatal("ключ не помечен отозванным")
	}
}

func TestCannotRevokeLastOwner(t *testing.T) {
	n := newNetwork(t)
	if _, err := n.apply(n.owners[0], KindAdminRevoke, AdminRevoke{KeyID: n.owners[1].KeyID()}); err != nil {
		t.Fatalf("отзыв второго владельца: %v", err)
	}
	_, err := n.apply(n.owners[0], KindAdminRevoke, AdminRevoke{KeyID: n.owners[0].KeyID()})
	if !errors.Is(err, ErrLastOwner) {
		t.Fatalf("последний владелец отозван — сеть осталась бы без управления: %v", err)
	}
}

func TestGapInSequenceIsReported(t *testing.T) {
	n := newNetwork(t)
	// Счётчик владельца после генезиса равен 1; собираем запись с третьим номером.
	op, err := NewOp(n.owners[0], KindClientAdd, 3, n.tick(), n.client("vasya"))
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	if _, err := n.state.Apply(op); !errors.Is(err, ErrGap) {
		t.Fatalf("пропуск в последовательности не замечен: %v", err)
	}
}

func TestReplayRejected(t *testing.T) {
	n := newNetwork(t)
	op := n.sign(n.owners[0], KindClientAdd, n.client("vasya"))
	if _, err := n.state.Apply(op); err != nil {
		t.Fatalf("первое применение: %v", err)
	}
	if _, err := n.state.Apply(op); !errors.Is(err, ErrReplay) {
		t.Fatalf("повтор записи принят: %v", err)
	}
}

// Два администратора правят одного клиента, а записи приходят в обратном порядке.
// Побеждать должна та, что сделана позже, а не та, что дошла позже.
func TestConcurrentEditsResolveByTime(t *testing.T) {
	n := newNetwork(t)
	base := n.client("vasya")
	if _, err := n.apply(n.owners[0], KindClientAdd, base); err != nil {
		t.Fatalf("создание клиента: %v", err)
	}

	early := base
	early.Limits = Limits{Devices: 1}
	earlyOp, err := NewOp(n.owners[0], KindClientUpdate, 3, n.clock.Add(time.Minute), early)
	if err != nil {
		t.Fatalf("сборка ранней правки: %v", err)
	}

	late := base
	late.Limits = Limits{Devices: 9}
	lateOp, err := NewOp(n.owners[1], KindClientUpdate, 1, n.clock.Add(2*time.Minute), late)
	if err != nil {
		t.Fatalf("сборка поздней правки: %v", err)
	}

	// Поздняя дошла первой.
	if eff, err := n.state.Apply(lateOp); err != nil || eff != EffectApplied {
		t.Fatalf("поздняя правка: %v (%s)", err, eff)
	}
	eff, err := n.state.Apply(earlyOp)
	if err != nil {
		t.Fatalf("ранняя правка: %v", err)
	}
	if eff != EffectSuperseded {
		t.Fatalf("ранняя правка перебила позднюю: %s", eff)
	}

	got, _ := n.state.Client("vasya")
	if got.Limits.Devices != 9 {
		t.Fatalf("победила не та правка: devices=%d", got.Limits.Devices)
	}

	// Счётчик всё равно должен сдвинуться: запись законна, просто устарела.
	if n.state.Counter(n.owners[0].KeyID()) != 3 {
		t.Fatalf("счётчик устаревшей записи не сдвинут: %d", n.state.Counter(n.owners[0].KeyID()))
	}
}

// При одинаковом времени решает идентификатор ключа — не ради справедливости, а чтобы
// у всех узлов получился один и тот же ответ.
//
// Ключи здесь обязаны быть одни и те же в обоих прогонах: генерируя новую пару на каждый
// прогон, тест сравнивал бы исходы двух разных сетей и падал на ровном месте.
func TestTiesAreBrokenDeterministically(t *testing.T) {
	n := newNetwork(t)

	base := n.client("vasya")
	addOp := n.sign(n.owners[0], KindClientAdd, base)
	at := n.clock.Add(time.Minute)

	a := base
	a.Limits = Limits{Devices: 1}
	opA, err := NewOp(n.owners[0], KindClientUpdate, 3, at, a)
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	b := base
	b.Limits = Limits{Devices: 2}
	opB, err := NewOp(n.owners[1], KindClientUpdate, 1, at, b)
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}

	// Один и тот же набор записей, разный порядок получения — как у двух узлов сети.
	replay := func(order ...*Op) Client {
		t.Helper()
		st := NewState()
		for _, op := range append([]*Op{n.genesisOp, addOp}, order...) {
			if _, err := st.Apply(op); err != nil {
				t.Fatalf("применение: %v", err)
			}
		}
		c, ok := st.Client("vasya")
		if !ok {
			t.Fatal("клиент пропал")
		}
		return c
	}

	forward := replay(opA, opB)
	backward := replay(opB, opA)
	if forward.Limits.Devices != backward.Limits.Devices {
		t.Fatalf("порядок получения решил исход: %d против %d",
			forward.Limits.Devices, backward.Limits.Devices)
	}
}

func TestUpdateOfMissingObjectRejected(t *testing.T) {
	n := newNetwork(t)
	if _, err := n.apply(n.owners[0], KindClientUpdate, n.client("ghost")); !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("правка несуществующего клиента принята: %v", err)
	}
}

// Идентификаторы намеренно узкие: они едут в логи, в имена файлов и в ссылки, поэтому
// кириллица и пробелы в них не допускаются, а вот подпись человека — свободная.
func TestClientIDIsRestrictedButLabelIsNot(t *testing.T) {
	n := newNetwork(t)
	c := n.client("vasya")
	c.Label = "Вася, телефон жены"
	if _, err := n.apply(n.owners[0], KindClientAdd, c); err != nil {
		t.Fatalf("свободная подпись отвергнута: %v", err)
	}

	// Собираем напрямую: n.apply роняет тест на ошибке сборки, а нам нужна сама ошибка.
	bad := n.client("вася")
	if _, err := NewOp(n.owners[0], KindClientAdd, 99, n.tick(), bad); err == nil {
		t.Fatal("кириллический идентификатор принят")
	}
}

func TestNodeLifecycle(t *testing.T) {
	n := newNetwork(t)
	node := Node{
		ID: "warsaw", PublicKey: testPubKey(t), Roles: []string{RoleEgress},
		Domain: "a.example.com", Endpoints: []string{"1.2.3.4:443"},
	}
	if _, err := n.apply(n.owners[0], KindNodeAdd, node); err != nil {
		t.Fatalf("добавление узла: %v", err)
	}
	if len(n.state.NodesWithRole(RoleEgress)) != 1 {
		t.Fatal("узел не значится выходным")
	}

	// Смена роли на лету — по решению 001 роль живёт в журнале, не в конфиге на машине.
	promoted := node
	promoted.Roles = []string{RoleIngress, RoleEgress}
	if _, err := n.apply(n.owners[0], KindNodeUpdate, promoted); err != nil {
		t.Fatalf("смена роли: %v", err)
	}
	if len(n.state.NodesWithRole(RoleIngress)) != 1 {
		t.Fatal("узел не стал входным")
	}

	if _, err := n.apply(n.owners[0], KindNodeRevoke, NodeRevoke{ID: "warsaw"}); err != nil {
		t.Fatalf("отзыв узла: %v", err)
	}
	if _, ok := n.state.Node("warsaw"); ok {
		t.Fatal("отозванный узел остался")
	}
}

// Один и тот же журнал обязан давать одно и то же состояние на любом узле.
func TestSameLogGivesSameState(t *testing.T) {
	n := newNetwork(t)
	var log []*Op

	genesisOp := n.sign(n.owners[0], KindClientAdd, n.client("a")) // счётчик 2
	log = append(log, genesisOp)
	log = append(log, n.sign(n.owners[1], KindClientAdd, n.client("b")))
	log = append(log, n.sign(n.owners[0], KindSettingsSet, Settings{BrutalUpMbps: 50, BrutalDownMbps: 200}))

	for _, op := range log {
		if _, err := n.state.Apply(op); err != nil {
			t.Fatalf("применение: %v", err)
		}
	}

	// Второй узел получает ту же генезис-запись и тот же журнал.
	other := NewState()
	if _, err := other.Apply(n.genesisOp); err != nil {
		t.Fatalf("генезис на втором узле: %v", err)
	}
	for _, op := range log {
		if _, err := other.Apply(op); err != nil {
			t.Fatalf("применение на втором узле: %v", err)
		}
	}
	if other.Genesis() != n.state.Genesis() {
		t.Fatal("отпечаток сети разъехался")
	}

	if len(other.Clients()) != len(n.state.Clients()) {
		t.Fatalf("клиенты разъехались: %d против %d", len(other.Clients()), len(n.state.Clients()))
	}
	if other.Settings() != n.state.Settings() {
		t.Fatalf("настройки разъехались: %+v против %+v", other.Settings(), n.state.Settings())
	}
	if other.Counters()[n.owners[0].KeyID()] != n.state.Counters()[n.owners[0].KeyID()] {
		t.Fatal("счётчики разъехались")
	}
}

// Запись неизвестного вида двигает счётчик: иначе всё, что этот ключ подпишет дальше,
// будет выглядеть пришедшим с пропуском, и узел встанет намертво.
func TestUnknownKindAdvancesCounter(t *testing.T) {
	n := newNetwork(t)
	// Счётчик ведём через тот же учёт, что и остальные записи, иначе следующая запись
	// разъедется с состоянием и тест поймает собственную ошибку вместо чужой.
	n.counter[n.owners[0].KeyID()]++
	op, err := NewOp(n.owners[0], Kind(60000), n.counter[n.owners[0].KeyID()], n.tick(), struct {
		Что string `json:"что"`
	}{"из будущего"})
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	eff, err := n.state.Apply(op)
	if err != nil {
		t.Fatalf("запись из будущего отвергнута: %v", err)
	}
	if eff != EffectUnknown {
		t.Fatalf("ожидали unknown, получили %s", eff)
	}
	if n.state.Counter(n.owners[0].KeyID()) != 2 {
		t.Fatal("счётчик не сдвинут — следующая запись покажется пришедшей с пропуском")
	}
	if _, err := n.apply(n.owners[0], KindClientAdd, n.client("vasya")); err != nil {
		t.Fatalf("следующая запись после неизвестной: %v", err)
	}
}
