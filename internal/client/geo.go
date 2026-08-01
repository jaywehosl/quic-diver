package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/jaywehosl/quic-diver/internal/geodata"
	"github.com/jaywehosl/quic-diver/internal/link"
	"github.com/jaywehosl/quic-diver/internal/node"
)

// Базы geosite/geoip отдельно от работающего клиента.
//
// # Зачем отдельный вход
//
// Правила со списками (`geosite:category-ads-all`) без баз не срабатывают никогда. Значит
// человек, впервые открывший маршрутизацию, должен суметь их скачать — и до того, как что-то
// настроил, и до того, как вообще подключился.
//
// Туннель для этого не нужен: базы качаются по связи с узлом, а не через интерфейс. Это видно
// по setupGeo — там HTTP ходит через link.Conn, и туннель поднимается позже. Здесь то же
// самое, только без всего остального: подняли связь, скачали, разошлись.
//
// На телефоне это ещё и означает, что разрешение на VPN спрашивать не надо: трафик идёт
// обычным сокетом приложения.

// GeoStatus — что известно о базах.
type GeoStatus struct {
	// Installed — установленная версия. Пустая означает, что баз нет.
	Installed string `json:"installed"`
	// Latest — версия в источнике. Пустая означает, что свериться не вышло.
	Latest string `json:"latest"`
	// Sites и IPs — сколько списков доменов и подсетей загружено.
	Sites int `json:"sites"`
	IPs   int `json:"ips"`
	// CheckedUnix — когда сверялись с источником, в секундах эпохи.
	CheckedUnix int64 `json:"checked_unix"`
	// Err — почему не вышло свериться. Пустая строка означает, что вышло.
	Err string `json:"err,omitempty"`
}

// Missing сообщает, что баз нет вовсе.
func (s GeoStatus) Missing() bool { return s.Installed == "" }

// HasUpdate сообщает, что в источнике есть версия свежее.
func (s GeoStatus) HasUpdate() bool {
	return s.Latest != "" && s.Installed != "" && s.Latest > s.Installed
}

// JSON отдаёт состояние строкой — для моста в приложение.
func (s GeoStatus) JSON() string {
	raw, err := json.Marshal(s)
	if err != nil {
		return `{"installed":""}`
	}
	return string(raw)
}

// LocalGeo смотрит, что лежит на диске, никуда не ходя.
//
// Нужно, чтобы экран открылся сразу: поход к источнику стоит секунды, а ответ «базы есть»
// известен и так.
func LocalGeo(dir string, log *slog.Logger) GeoStatus {
	dir = geoDir(dir)
	u := &geodata.Updater{Dir: dir, Mode: geodata.ModeOff, Log: log}

	status := u.Check(context.Background())
	out := GeoStatus{Installed: status.Installed}
	if out.Missing() {
		return out
	}

	sets, err := u.Load()
	if err != nil {
		out.Err = err.Error()
		return out
	}
	out.Sites = len(sets.SiteLists())
	out.IPs = len(sets.IPLists())
	return out
}

// FetchGeo скачивает базы, не поднимая туннеля.
//
// Связь с сетью поднимается своя и закрывается по возвращении: вызов самодостаточен и не
// требует, чтобы клиент уже работал. Если он всё-таки работает, вызывать это не надо —
// подхватывать новые базы на ходу умеет сам клиент.
func FetchGeo(ctx context.Context, o Options) (GeoStatus, error) {
	o = o.withDefaults()

	log := o.Log
	if log == nil {
		log = newLogger(o.LogLevel)
	}

	net, err := resolveNetwork(o, log)
	if err != nil {
		return GeoStatus{}, err
	}

	conn, err := link.New(link.Config{
		Targets:   net.targets,
		TLS:       &tls.Config{},
		Self:      net.self,
		OnConnect: func(c *node.Conn) { c.SetLog(log) },
		Log:       log,
	})
	if err != nil {
		return GeoStatus{}, err
	}

	linkCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() { _ = conn.Run(linkCtx) }()

	if _, err := waitFirst(ctx, conn); err != nil {
		return GeoStatus{}, fmt.Errorf("связи с сетью нет: %w", err)
	}

	dir := geoDir(o.GeoDir)
	u := &geodata.Updater{
		Dir:  dir,
		Mode: geodata.ModeAuto,
		HTTP: geoHTTP(conn, o.ViaExit),
		Log:  log,
	}

	status := u.Check(ctx)
	if status.Err != nil {
		return GeoStatus{Installed: status.Installed, Err: status.Err.Error()},
			fmt.Errorf("свериться с источником не вышло: %w", status.Err)
	}
	if status.Missing() || status.HasUpdate() {
		log.Info("качаю базы", "version", status.Latest)
		if err := u.Download(ctx, status.Latest); err != nil {
			return GeoStatus{Installed: status.Installed}, err
		}
	}

	out := LocalGeo(dir, log)
	out.Latest = status.Latest
	out.CheckedUnix = time.Now().Unix()
	log.Info("базы на месте", "version", out.Installed, "списков_доменов", out.Sites,
		"списков_подсетей", out.IPs)
	return out, nil
}

// GeoLists перечисляет имена списков из загруженных баз.
//
// Имена отдаются как есть: их полторы тысячи, они приходят из чужой базы и меняются вместе с
// ней (см. geodata.SiteLists).
func GeoLists(dir string, log *slog.Logger) (sites, ips []string, err error) {
	u := &geodata.Updater{Dir: geoDir(dir), Mode: geodata.ModeOff, Log: log}
	sets, err := u.Load()
	if err != nil {
		return nil, nil, err
	}
	return sets.SiteLists(), sets.IPLists(), nil
}

// geoDir подставляет каталог по умолчанию.
func geoDir(dir string) string {
	if dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".qdiver", "geo")
	}
	return filepath.Join(home, ".qdiver", "geo")
}

// geoHTTP собирает клиента, ходящего через сеть.
func geoHTTP(l *link.Link, viaExit bool) *http.Client {
	return &http.Client{
		Timeout: 3 * time.Minute,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := l.Conn(ctx)
				if err != nil {
					return nil, err
				}
				return conn.DialContext(ctx, network, addr, viaExit)
			},
			// Внутри уже QUIC: второй слой мультиплексирования ничего не даст, а сюрпризов
			// добавит.
			ForceAttemptHTTP2: false,
		},
	}
}
