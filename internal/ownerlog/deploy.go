package ownerlog

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Ключ развёртывания (решение 007 §3.1).
//
// # Что в нём
//
// Отпечаток сети, домен, имя узла, роль, потолки BRUTAL и адреса живых узлов. Скрипт на сервере
// раскладывает это в конфиг и стартует узел.
//
// # Почему он не шифруется
//
// Секретного в нём нет ничего: отпечаток — хеш публичной записи, остальное человек только что
// ввёл сам. Но главное не в этом. Расшифровывать будет скрипт, лежащий в открытом репозитории,
// значит ключ расшифровки лежал бы там же — замок с ключом на двери. Хуже того, он создавал бы
// ложное чувство защиты.
//
// Опасна не утечка такого ключа, а подмена: человеку подсунули чужой, он развернул узел чужой
// сети. От этого шифрование не спасает вовсе; спасает то, что ключ приходит из своего же
// приложения на свой же экран.
//
// # Зачем контрольная сумма
//
// Ключ переносят руками — копированием, а иногда и переписыванием. Опечатка в base64 даёт не
// ошибку, а другой набор байт, и без суммы узел молча поднялся бы с испорченным отпечатком,
// после чего не принял бы журнал и никто не понял бы почему.

// DeployScheme — приставка ключа развёртывания. Ссылкой он не является: его вводят в скрипт.
const DeployScheme = "qdnode:"

// maxDeploy ограничивает разбираемый ключ.
const maxDeploy = 64 << 10

// Ошибки разбора ключа развёртывания.
var (
	ErrNotDeployKey = errors.New("ownerlog: это не ключ развёртывания")
	ErrDeployBroken = errors.New("ownerlog: ключ развёртывания испорчен — проверь, всё ли скопировалось")
)

// Deploy — что скрипт раскладывает по конфигу узла.
type Deploy struct {
	// Version — версия формата. Меняется, когда старый скрипт перестал бы понимать новый ключ.
	Version int `json:"version"`
	// Network — имя сети, для человека и для журнала службы.
	Network string `json:"network"`
	// Genesis — отпечаток сети. Ради него всё и затевалось: узел примет только тот журнал,
	// чей генезис даёт это число.
	Genesis oplog.Fingerprint `json:"genesis"`
	// ID — как узел зовут в сети.
	ID string `json:"id"`
	// Domain — имя, на которое узел выпустит сертификат.
	Domain string `json:"domain"`
	// Roles — ingress, egress или обе.
	Roles []string `json:"roles"`
	// Settings — потолки BRUTAL и параметры службы имён на момент выдачи ключа.
	//
	// Дубликат того, что и так приедет журналом. Нужен затем, чтобы узел поднялся с верными
	// числами сразу, а не после первой сверки: журнал приходит секундами позже старта.
	Settings oplog.Settings `json:"settings,omitempty"`
	// Peers — адреса живых узлов. Новый узел стучится к ним сам и забирает журнал; для
	// первого узла список пуст, и журнал ему отдаёт клиент (решение 007 §3.4).
	Peers []string `json:"peers,omitempty"`
}

// DeployVersion — текущая версия формата ключа развёртывания.
const DeployVersion = 1

func (d Deploy) validate() error {
	if d.Version != DeployVersion {
		return fmt.Errorf("%w: версия %d, эта сборка знает %d", ErrDeployBroken, d.Version, DeployVersion)
	}
	if d.Genesis.IsZero() {
		return fmt.Errorf("%w: нет отпечатка сети", ErrDeployBroken)
	}
	if strings.TrimSpace(d.ID) == "" {
		return fmt.Errorf("%w: нет имени узла", ErrDeployBroken)
	}
	if strings.TrimSpace(d.Domain) == "" {
		return fmt.Errorf("%w: нет домена", ErrDeployBroken)
	}
	if len(d.Roles) == 0 {
		return fmt.Errorf("%w: не задана роль узла", ErrDeployBroken)
	}
	return nil
}

// EncodeDeploy собирает ключ развёртывания.
//
// Кодировка та же, что у бандла: gzip, затем base64 — с той разницей, что тело открытое и к
// нему приписана контрольная сумма.
func EncodeDeploy(d Deploy) (string, error) {
	d.Version = DeployVersion
	if err := d.validate(); err != nil {
		return "", err
	}

	raw, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("ownerlog: сборка ключа развёртывания: %w", err)
	}

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return "", fmt.Errorf("ownerlog: сжатие: %w", err)
	}
	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("ownerlog: сжатие: %w", err)
	}

	body := buf.Bytes()
	sum := crc32.ChecksumIEEE(body)
	return fmt.Sprintf("%s%s.%08x", DeployScheme, base64.RawURLEncoding.EncodeToString(body), sum), nil
}

// DecodeDeploy разбирает ключ развёртывания.
func DecodeDeploy(key string) (Deploy, error) {
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, DeployScheme) {
		return Deploy{}, ErrNotDeployKey
	}
	key = strings.TrimPrefix(key, DeployScheme)

	encoded, sumHex, ok := strings.Cut(key, ".")
	if !ok {
		return Deploy{}, fmt.Errorf("%w: нет контрольной суммы", ErrDeployBroken)
	}

	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Deploy{}, fmt.Errorf("%w: %v", ErrDeployBroken, err)
	}

	var want uint32
	if _, err := fmt.Sscanf(sumHex, "%08x", &want); err != nil {
		return Deploy{}, fmt.Errorf("%w: контрольная сумма не разбирается", ErrDeployBroken)
	}
	if got := crc32.ChecksumIEEE(body); got != want {
		// Именно тот случай, ради которого сумма и нужна: скопировалось не всё либо
		// переносили руками и ошиблись знаком.
		return Deploy{}, fmt.Errorf("%w: сумма %08x, ожидалась %08x", ErrDeployBroken, got, want)
	}

	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return Deploy{}, fmt.Errorf("%w: %v", ErrDeployBroken, err)
	}
	defer zr.Close()

	raw, err := io.ReadAll(io.LimitReader(zr, maxDeploy))
	if err != nil {
		return Deploy{}, fmt.Errorf("%w: %v", ErrDeployBroken, err)
	}

	var d Deploy
	if err := json.Unmarshal(raw, &d); err != nil {
		return Deploy{}, fmt.Errorf("%w: %v", ErrDeployBroken, err)
	}
	if err := d.validate(); err != nil {
		return Deploy{}, err
	}
	return d, nil
}

// DeployFor собирает ключ развёртывания для нового узла по состоянию журнала.
//
// Адреса живых узлов берутся отсюда же: второму и следующим узлам они нужны, чтобы забрать
// журнал у соседа, не дожидаясь клиента.
func (j *Journal) DeployFor(id, domain string, roles []string) Deploy {
	st := j.State()
	d := Deploy{
		Version:  DeployVersion,
		Network:  st.Network(),
		Genesis:  st.Genesis(),
		ID:       id,
		Domain:   domain,
		Roles:    roles,
		Settings: st.Settings(),
	}
	for _, n := range st.Nodes() {
		d.Peers = append(d.Peers, n.Endpoints...)
	}
	return d
}
