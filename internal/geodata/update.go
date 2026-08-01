package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Обновление баз.
//
// Базы берутся у Loyalsoldier — те же файлы, к которым привыкли пользователи v2fly. Три
// решения, каждое со своей причиной:
//
// Свежесть сверяется при каждом запуске, даже когда базы уже стоят. Они обновляются по
// нескольку раз в сутки, и разница между вчерашней и сегодняшней версией — это ровно те
// домены, ради которых правило и писали.
//
// Качаем **через туннель**, а не напрямую. Клиент к этому моменту уже подключён к узлу, а
// GitHub с машины под фильтрацией может и не открыться — проверено на qdiver2, где YouTube и
// rutracker напрямую недоступны. Заодно не приходится объяснять, почему клиент лезет наружу
// мимо собственной сети.
//
// Отказ проверки никогда не мешает запуску. Не свернулись — работаем на том, что есть, и
// пишем строку в журнал.

// Mode — как вести себя с обновлениями.
type Mode string

const (
	// ModeAsk — проверить и спросить. Умолчание.
	//
	// Спросить можно, только когда есть кого: клиент в терминале вопрос покажет, служба под
	// systemd — нет, и вопрос в никуда означал бы, что клиент встал навсегда. Без терминала
	// режим качает и говорит об этом; кому и это лишнее — ставит off.
	ModeAsk Mode = "ask"
	// ModeAuto — проверить и обновить молча.
	ModeAuto Mode = "auto"
	// ModeOff — не проверять вовсе. Для тех, кому важно, чтобы клиент никуда не ходил.
	ModeOff Mode = "off"
)

// ParseMode разбирает режим.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case "", ModeAsk:
		return ModeAsk, nil
	case ModeAuto:
		return ModeAuto, nil
	case ModeOff:
		return ModeOff, nil
	default:
		return "", fmt.Errorf("geodata: неизвестный режим обновления %q", s)
	}
}

// Источник баз. Вынесен в переменные, чтобы можно было подменить в тестах и на случай
// переезда репозитория.
var (
	ReleaseAPI = "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest"
	SiteFile   = "geosite.dat"
	IPFile     = "geoip.dat"
)

// Updater следит за свежестью баз.
type Updater struct {
	// Dir — куда класть базы.
	Dir string
	// Mode — как себя вести.
	Mode Mode
	// HTTP — чем ходить в сеть. Ожидается клиент, ходящий через туннель.
	HTTP *http.Client
	// Log — куда писать.
	Log *slog.Logger
}

// state — то, что записано рядом с базами.
type state struct {
	Version   string    `json:"version"`
	CheckedAt time.Time `json:"checked_at"`
	SiteHash  string    `json:"site_hash"`
	IPHash    string    `json:"ip_hash"`
}

// Status — что выяснила проверка.
type Status struct {
	// Installed — версия, которая лежит на диске. Пусто, если баз нет.
	Installed string
	// Latest — версия в источнике. Пусто, если свериться не удалось.
	Latest string
	// CheckedAt — когда в последний раз удалось свериться с источником.
	//
	// Нулевое время означает, что не сверялись ни разу. По этой метке считается интервал
	// «проверять не чаще, чем раз в…»: без неё «раз в неделю» означало бы «при каждом
	// запуске», потому что о прошлой проверке нечему было бы помнить.
	CheckedAt time.Time
	// Err — почему не удалось свериться. Не мешает работе.
	Err error
}

// HasUpdate сообщает, есть ли что скачивать.
func (s Status) HasUpdate() bool {
	return s.Latest != "" && s.Latest != s.Installed
}

// Missing сообщает, что баз нет вовсе.
func (s Status) Missing() bool { return s.Installed == "" }

// Check сверяет установленную версию с источником.
//
// Ошибка сети возвращается в Status, а не наружу: клиент обязан подняться и без обновления.
func (u *Updater) Check(ctx context.Context) Status {
	saved := u.readState()
	st := Status{Installed: u.installed(), CheckedAt: saved.CheckedAt}

	if u.Mode == ModeOff {
		return st
	}

	latest, err := u.latest(ctx)
	if err != nil {
		st.Err = err
		return st
	}
	st.Latest = latest

	// Метка двигается на каждой удачной сверке, а не только на закачке. Иначе базы, которые
	// не менялись месяц, выглядели бы «не проверявшимися месяц», и клиент ходил бы к
	// источнику при каждом запуске вопреки заданному интервалу.
	u.touch(latest)
	st.CheckedAt = time.Now().UTC()
	return st
}

// Due сообщает, пора ли сверяться с источником.
//
// Баз нет — пора всегда: без них правила со списками не работают, и ждать неделю бессмысленно.
func (u *Updater) Due(interval time.Duration) bool {
	if u.installed() == "" {
		return true
	}
	if interval <= 0 {
		return true
	}
	checked := u.readState().CheckedAt
	return checked.IsZero() || time.Since(checked) >= interval
}

// readState читает то, что записано рядом с базами. Отсутствие файла — не ошибка.
func (u *Updater) readState() state {
	var s state
	raw, err := os.ReadFile(filepath.Join(u.Dir, "state.json"))
	if err != nil {
		return s
	}
	_ = json.Unmarshal(raw, &s)
	return s
}

// touch отмечает время удачной сверки, не трогая ни версию, ни отпечатки.
func (u *Updater) touch(latest string) {
	s := u.readState()
	if s.Version == "" {
		// Баз нет — отмечать нечего: файл состояния появится вместе с ними.
		return
	}
	s.CheckedAt = time.Now().UTC()

	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	// Ошибку записи глотаем намеренно: не сохранилась метка — в следующий раз просто
	// сверимся раньше, чем могли бы. Ронять из-за этого проверку обновлений незачем.
	_ = os.WriteFile(filepath.Join(u.Dir, "state.json"), raw, 0o600)
}

func (u *Updater) installed() string {
	raw, err := os.ReadFile(filepath.Join(u.Dir, "state.json"))
	if err != nil {
		return ""
	}
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	// Версия без файлов ничего не значит: базы могли снести руками.
	for _, name := range []string{SiteFile, IPFile} {
		if _, err := os.Stat(filepath.Join(u.Dir, name)); err != nil {
			return ""
		}
	}
	return s.Version
}

// latest спрашивает у источника номер последнего выпуска.
func (u *Updater) latest(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ReleaseAPI, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := u.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("geodata: запрос версии: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("geodata: источник ответил %s", resp.Status)
	}

	var release struct {
		Tag string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&release); err != nil {
		return "", fmt.Errorf("geodata: разбор ответа: %w", err)
	}
	if release.Tag == "" {
		return "", fmt.Errorf("geodata: источник не назвал версию")
	}
	return release.Tag, nil
}

// Download качает базы указанной версии и раскладывает их.
//
// Файлы сперва пишутся во временные и переименовываются только целиком. Оборванная закачка
// не должна оставить клиента с половиной списка: он молча перестал бы ловить часть доменов,
// и заметить это было бы нечем.
func (u *Updater) Download(ctx context.Context, version string) error {
	if err := os.MkdirAll(u.Dir, 0o700); err != nil {
		return fmt.Errorf("geodata: каталог баз: %w", err)
	}

	base := fmt.Sprintf("https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/%s/", version)
	hashes := make(map[string]string, 2)

	for _, name := range []string{SiteFile, IPFile} {
		sum, err := u.fetchFile(ctx, base+name, filepath.Join(u.Dir, name))
		if err != nil {
			return err
		}
		hashes[name] = sum
	}

	s := state{
		Version:   version,
		CheckedAt: time.Now().UTC(),
		SiteHash:  hashes[SiteFile],
		IPHash:    hashes[IPFile],
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(u.Dir, "state.json"), raw, 0o600); err != nil {
		return fmt.Errorf("geodata: запись состояния: %w", err)
	}

	u.log().Info("базы обновлены", "version", version)
	return nil
}

func (u *Updater) fetchFile(ctx context.Context, url, dst string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := u.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("geodata: загрузка %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("geodata: загрузка %s: %s", url, resp.Status)
	}

	tmp, err := os.CreateTemp(u.Dir, "download-*")
	if err != nil {
		return "", fmt.Errorf("geodata: временный файл: %w", err)
	}
	defer os.Remove(tmp.Name())

	hash := sha256.New()
	// Потолок на всякий случай: базы весят единицы мегабайт, и сотня — это уже не база.
	if _, err := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(resp.Body, 128<<20)); err != nil {
		tmp.Close()
		return "", fmt.Errorf("geodata: чтение %s: %w", url, err)
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", fmt.Errorf("geodata: перенос %s: %w", dst, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Load читает базы с диска.
func (u *Updater) Load() (*Sets, error) {
	siteRaw, err := os.ReadFile(filepath.Join(u.Dir, SiteFile))
	if err != nil {
		return nil, fmt.Errorf("geodata: чтение списков доменов: %w", err)
	}
	ipRaw, err := os.ReadFile(filepath.Join(u.Dir, IPFile))
	if err != nil {
		return nil, fmt.Errorf("geodata: чтение списков подсетей: %w", err)
	}

	sites, err := ParseSites(siteRaw)
	if err != nil {
		return nil, err
	}
	ips, err := ParseIPs(ipRaw)
	if err != nil {
		return nil, err
	}

	s := New()
	s.LoadSites(sites)
	s.LoadIPs(ips)
	return s, nil
}

func (u *Updater) client() *http.Client {
	if u.HTTP != nil {
		return u.HTTP
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

func (u *Updater) log() *slog.Logger {
	if u.Log != nil {
		return u.Log
	}
	return slog.Default()
}
