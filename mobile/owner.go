package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jaywehosl/quic-diver/internal/bundle"
	"github.com/jaywehosl/quic-diver/internal/client"
	// Алиас: в этом же пакете есть переменная control — живой рычаг работающего клиента.
	// Имена столкнулись бы, и понятнее переименовать пакет, чем переменную, которую зовут из
	// десятка мест.
	qdcontrol "github.com/jaywehosl/quic-diver/internal/control"
	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/ownerlog"
)

// Создание сети и включение узлов — со стороны приложения (решение 007 §2 и §3).
//
// Ключи владельца рождаются здесь же, на устройстве, офлайн. Сервера в этот момент нет ни
// одного: узел не может выдать ссылку владельцу, потому что не знает ни сети, ни ключей.
//
// Журнал сети живёт файлом в каталоге состояния — тем же, где лежат сведения о сети. SQLite для
// него не нужен: записей десятки, и открывают их раз в неделю (см. internal/ownerlog).

// journalFile — имя файла журнала в каталоге состояния.
const journalFile = "oplog.bin"

// ownerKeyFile — приватный ключ рабочего владельца.
//
// Лежит рядом с журналом, а не в SharedPreferences: там он оказался бы в резервной копии
// системы, то есть в чужом облаке. Приложение объявляет `allowBackup=false`, но полагаться на
// один флаг там, где речь о ключе от всей сети, не стоит.
const ownerKeyFile = "owner.key"

// spareKeyFile — запасной ключ владельца, придержанный до выдачи ссылок.
//
// Живёт ровно между созданием сети и включением первого узла: раньше ссылку выдавать нечем —
// в ней не было бы ни одного адреса, — а после выдачи хранить его здесь незачем и вредно.
const spareKeyFile = "owner-spare.key"

// CreateNetwork создаёт сеть на устройстве.
//
// Возвращает JSON: {"genesis":…, "working":…, "spare":…}. Обе ссылки под заданным паролем;
// рабочая остаётся в приложении, запасную человек уносит.
//
// Долгий вызов — шифрование ссылки паролем стоит около секунды на ключ, — и звать его с
// главного потока нельзя.
func CreateNetwork(name, password string, brutalUp, brutalDown, brutalMesh int) (string, error) {
	mu.Lock()
	dir := prefs.stateDir
	mu.Unlock()

	if strings.TrimSpace(name) == "" {
		return "", errors.New("не задано имя сети")
	}
	if dir == "" {
		return "", errors.New("не задан каталог состояния")
	}
	if j, err := ownerlog.Open(filepath.Join(dir, journalFile)); err == nil && !j.Genesis().IsZero() {
		// Вторая сеть поверх первой стёрла бы ключи от первой — и никакого способа их вернуть
		// не осталось бы. Пусть человек сначала явно сбросит данные.
		return "", errors.New("сеть уже создана: сначала сбрось данные")
	}

	res, err := ownerlog.Create(ownerlog.Params{
		Network:  name,
		Password: password,
		Settings: oplog.Settings{
			BrutalUpMbps:   brutalUp,
			BrutalDownMbps: brutalDown,
			BrutalMeshMbps: brutalMesh,
		},
	})
	if err != nil {
		return "", err
	}

	if err := res.Journal.Save(filepath.Join(dir, journalFile)); err != nil {
		return "", err
	}
	if err := saveOwnerKey(dir, res.WorkingKey); err != nil {
		return "", err
	}
	if err := saveSpareKey(dir, res.SpareKey); err != nil {
		return "", err
	}

	out, err := json.Marshal(struct {
		Genesis string `json:"genesis"`
		Network string `json:"network"`
	}{
		Genesis: res.Genesis.String(),
		Network: name,
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// IssueOwnerBundles выдаёт обе ссылки владельца — после того, как первый узел в сети.
//
// Ссылки собираются из журнала и несут узлы, их адреса и потолки. До появления узла выдавать
// нечего: ключ без адреса никуда не ведёт.
//
// Пароль тот же, что человек задал при создании сети: спрашивать его второй раз значило бы
// завести две разные тайны там, где нужна одна.
//
// Долгий вызов — шифрование стоит около секунды на ссылку.
func IssueOwnerBundles(password string) (string, error) {
	j, dir, err := ownerJournal()
	if err != nil {
		return "", err
	}
	working, err := loadOwnerKey(dir)
	if err != nil {
		return "", err
	}
	spare, err := loadSpareKey(dir)
	if err != nil {
		return "", fmt.Errorf("запасной ключ потерян: %w", err)
	}

	workingURI, spareURI, err := ownerlog.IssueBundles(j, working, spare, password)
	if err != nil {
		return "", err
	}
	// Запасной ключ уходит с устройства: вся его ценность в том, что он лежит там, куда не
	// дотянется этот телефон.
	dropSpareKey(dir)

	out, err := json.Marshal(struct {
		Network string `json:"network"`
		Genesis string `json:"genesis"`
		Working string `json:"working"`
		Spare   string `json:"spare"`
	}{
		Network: j.State().Network(),
		Genesis: j.Genesis().String(),
		Working: workingURI,
		Spare:   spareURI,
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// DeployKey собирает ключ развёртывания для нового узла.
//
// Ключ не шифруется: секретного в нём нет, а расшифровывать его будет скрипт из открытого
// репозитория (решение 007 §3.1). Опасна не утечка, а подмена — потому ключ и приходит из
// своего же приложения на свой же экран.
func DeployKey(id, domain, role string) (string, error) {
	j, _, err := ownerJournal()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(id) == "" || strings.TrimSpace(domain) == "" {
		return "", errors.New("нужны имя узла и домен")
	}

	roles, err := rolesOf(role)
	if err != nil {
		return "", err
	}
	return ownerlog.EncodeDeploy(j.DeployFor(id, domain, roles))
}

// AdoptNode включает поднявшийся узел в сеть.
//
// Спрашивает у него имя, домен и публичный ключ, подписывает запись ключом владельца и
// заливает журнал целиком. Отвечает только узел, ещё не включённый в сеть.
//
// code — восемь знаков, напечатанных скриптом развёртывания в терминале. Пустой означает, что
// сверки нет и узел берётся на веру по TLS.
//
// Долгий вызов: связь с сервером. Возвращает JSON с тем, что записано.
func AdoptNode(addr, role, code string, insecure bool) (string, error) {
	j, dir, err := ownerJournal()
	if err != nil {
		return "", err
	}
	key, err := loadOwnerKey(dir)
	if err != nil {
		return "", err
	}
	roles, err := rolesOf(role)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), adoptTimeout)
	defer cancel()

	record, err := j.Adopt(ctx, ownerlog.AdoptParams{
		Addr:     addr,
		Roles:    roles,
		Code:     code,
		OwnerKey: key,
		Insecure: insecure,
	})

	// Несовпадение кода — не сбой связи, а ответ: на том конце не тот узел. Отдаётся не
	// исключением, а полем, потому что приложению с ним обращаться иначе — прекратить
	// повторы. Ошибка моста строкой этого различия не даёт.
	//
	// Код, которым назвался тот конец, сюда не кладётся намеренно. Показать его значило бы
	// подсказать человеку, что́ ввести, чтобы «наконец получилось», — а получилось бы у него
	// включить в сеть чужой узел.
	if errors.Is(err, ownerlog.ErrWrongCode) {
		return `{"adopted":false,"wrong_code":true}`, nil
	}
	if err != nil {
		return "", err
	}
	if err := j.Save(filepath.Join(dir, journalFile)); err != nil {
		return "", err
	}

	// Узел записан в журнал — теперь о нём должна узнать клиентская половина приложения.
	//
	// Сама она не узнает никак: ссылку владелец выдал себе, когда узлов не существовало, и
	// Ingress в ней пуст навсегда. Снапшот тоже не поможет — чтобы его получить, надо к
	// кому-то подключиться, а подключаться не к кому ровно потому, что узлов нет. Круг
	// разрывается здесь: узлы лежат в журнале владельца, оттуда их и берём.
	if err := client.RememberNetwork(dir, qdcontrol.SnapshotOf(j.State()), slog.New(newHandler())); err != nil {
		return "", fmt.Errorf("узел в сети, но клиент о нём не узнал: %w", err)
	}

	out, err := json.Marshal(struct {
		Adopted   bool     `json:"adopted"`
		ID        string   `json:"id"`
		Domain    string   `json:"domain"`
		Roles     []string `json:"roles"`
		Endpoints []string `json:"endpoints"`
	}{
		Adopted:   true,
		ID:        record.ID,
		Domain:    record.Domain,
		Roles:     record.Roles,
		Endpoints: record.Endpoints,
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// adoptTimeout ограничивает включение узла целиком: спросить и залить журнал.
const adoptTimeout = 45 * time.Second

// OwnerStatus говорит, держит ли это устройство сеть.
//
// Отвечает JSON: {"owner":…, "network":…, "genesis":…, "nodes":…, "records":…}. Приложение по
// нему решает, показывать ли управление сетью.
func OwnerStatus() string {
	mu.Lock()
	dir := prefs.stateDir
	mu.Unlock()

	empty := `{"owner":false}`
	if dir == "" {
		return empty
	}
	j, err := ownerlog.Open(filepath.Join(dir, journalFile))
	if err != nil || j.Genesis().IsZero() {
		return empty
	}

	out, err := json.Marshal(struct {
		Owner   bool   `json:"owner"`
		Network string `json:"network"`
		Genesis string `json:"genesis"`
		Nodes   int    `json:"nodes"`
		Records int    `json:"records"`
	}{
		Owner:   true,
		Network: j.State().Network(),
		Genesis: j.Genesis().String(),
		Nodes:   len(j.State().Nodes()),
		Records: j.Len(),
	})
	if err != nil {
		return empty
	}
	return string(out)
}

// refreshFromOwnJournal обновляет сведения о сети из своего же журнала.
//
// Второе значение — брался ли этот путь вообще: журнала нет, значит устройство сетью не владеет
// и обновляться ему надо обычным способом, спросив узел.
func refreshFromOwnJournal() (string, bool, error) {
	mu.Lock()
	dir := prefs.stateDir
	mu.Unlock()

	if dir == "" {
		return "", false, nil
	}
	j, err := ownerlog.Open(filepath.Join(dir, journalFile))
	if err != nil || j.Genesis().IsZero() {
		return "", false, nil
	}

	snap := qdcontrol.SnapshotOf(j.State())
	if len(snap.Nodes) == 0 {
		return "", true, errors.New("в сети пока нет ни одного входного узла — разверни его")
	}
	if err := client.RememberNetwork(dir, snap, slog.New(newHandler())); err != nil {
		return "", true, err
	}
	return client.LocalNetwork(dir, slog.New(newHandler())).JSON(), true, nil
}

// WipeOwner стирает сеть с этого устройства: журнал, ключ владельца, запомненные узлы.
//
// Нужно затем, что создать вторую сеть поверх первой нельзя — это стёрло бы ключи от первой без
// всякой возможности их вернуть, — а прерванная на середине попытка оставляет ровно такое
// состояние: сеть создана, узлов нет, идти некуда. Без явного сброса человеку оставалось бы
// чистить данные приложения через системные настройки.
//
// Узлы, уже стоящие на серверах, при этом остаются без владельца: их журнал никуда не девается,
// а вот подписывать новые записи для них станет некому.
func WipeOwner() error {
	mu.Lock()
	dir := prefs.stateDir
	mu.Unlock()

	if dir == "" {
		return errors.New("не задан каталог состояния")
	}
	var failed error
	for _, name := range []string{journalFile, ownerKeyFile, "network.json"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			failed = err
		}
	}
	return failed
}

// AdoptOwnerBundle принимает ссылку владельца на другом устройстве.
//
// Нужен, когда человек ставит приложение заново или переносит управление на второй телефон:
// ключ приезжает ссылкой, а журнал — от любого живого узла, сверкой (решение 007 §1.1).
func AdoptOwnerBundle(uri, password string) error {
	mu.Lock()
	dir := prefs.stateDir
	mu.Unlock()

	if dir == "" {
		return errors.New("не задан каталог состояния")
	}
	b, err := bundle.Decode(uri, password)
	if err != nil {
		return err
	}
	if !b.Owner {
		return errors.New("это обычная ссылка клиента, а не ссылка владельца")
	}
	return saveOwnerKey(dir, b.ClientKey)
}

// ownerJournal открывает журнал сети и проверяет, что сеть вообще есть.
func ownerJournal() (*ownerlog.Journal, string, error) {
	mu.Lock()
	dir := prefs.stateDir
	mu.Unlock()

	if dir == "" {
		return nil, "", errors.New("не задан каталог состояния")
	}
	j, err := ownerlog.Open(filepath.Join(dir, journalFile))
	if err != nil {
		return nil, "", err
	}
	if j.Genesis().IsZero() {
		return nil, "", ownerlog.ErrNoGenesis
	}
	return j, dir, nil
}

// rolesOf переводит выбор с экрана в роли записи журнала.
func rolesOf(role string) ([]string, error) {
	switch strings.TrimSpace(role) {
	case "ingress", "":
		// Пустое — входной: первый узел сети всегда входной, роль у него не спрашивают.
		return []string{"ingress"}, nil
	case "egress":
		return []string{"egress"}, nil
	case "both":
		return []string{"ingress", "egress"}, nil
	default:
		return nil, fmt.Errorf("неизвестная роль %q", role)
	}
}
