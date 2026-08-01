// Package link держит связь клиента с сетью.
//
// Соединение с узлом — вещь смертная: человек ушёл из дома, телефон переключился с Wi-Fi на
// соты, узел ушёл на перезапуск. Всё, что выше, при этом жить обязано: туннель поднят,
// маршруты стоят, приложения работают. Поэтому связь и её потребители разделены — потребитель
// просит текущее соединение перед каждым потоком и не знает, сколько раз оно менялось.
package link

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/node"
)

// Отступы между попытками.
//
// Растут, чтобы клиент в мёртвой сети не превратился в источник трафика. Потолок небольшой:
// связь возвращается внезапно, и ждать после её появления минуту — никуда не годится.
const (
	minBackoff = 500 * time.Millisecond
	maxBackoff = 15 * time.Second
)

// dialTimeout ограничивает одну гонку целиком.
const dialTimeout = 30 * time.Second

// ErrClosed означает, что связь больше не поддерживается.
var ErrClosed = errors.New("link: связь закрыта")

// Config — что нужно, чтобы держать связь.
type Config struct {
	// Targets — входные узлы сети. Гонка обращается ко всем сразу.
	Targets []node.Target
	// TLS — доверие к сертификатам узлов. ServerName проставляет гонка сама.
	TLS *tls.Config
	// Self — кем представляется клиент.
	Self hello.Identity
	// SendMbps — потолок BRUTAL для отправки клиентом (решение 006). Это «вверх» из
	// настроек сети. Ноль означает обычный Cubic.
	SendMbps int
	// OnConnect вызывается на каждом новом соединении, в том числе после обрыва.
	// Пустой — ничего не делать.
	OnConnect func(*node.Conn)
	// OnDisconnect вызывается при потере связи. Пустой — ничего не делать.
	OnDisconnect func()
	// Log — куда писать.
	Log *slog.Logger
}

// Link — живая связь с сетью.
type Link struct {
	cfg Config
	log *slog.Logger

	mu   sync.RWMutex
	conn *node.Conn
	// targets — узлы для гонки. Живут здесь, а не в cfg, потому что меняются на ходу:
	// сеть присылает свой список снапшотом (решение 007 §4).
	targets []node.Target
	changed chan struct{}
	closed  bool
}

// New собирает связь. Соединение появится, когда запустят Run.
func New(cfg Config) (*Link, error) {
	if len(cfg.Targets) == 0 {
		return nil, node.ErrNoTargets
	}
	if cfg.TLS == nil {
		cfg.TLS = &tls.Config{}
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	return &Link{cfg: cfg, log: cfg.Log, targets: cfg.Targets, changed: make(chan struct{})}, nil
}

// Conn отдаёт текущее соединение, дожидаясь его появления.
//
// Ждать приходится не только в начале: после обрыва потоки, пришедшие раньше новой связи,
// подождут её здесь, а не получат отказ. Для человека разница ровно та же, что между
// «страница грузится дольше обычного» и «нет интернета».
func (l *Link) Conn(ctx context.Context) (*node.Conn, error) {
	for {
		l.mu.RLock()
		conn, closed, changed := l.conn, l.closed, l.changed
		l.mu.RUnlock()

		if closed {
			return nil, ErrClosed
		}
		if conn != nil {
			return conn, nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Current отдаёт текущее соединение, не дожидаясь его появления.
//
// Пустое означает, что связи сейчас нет — идёт гонка либо клиент только запустился. Тем, кому
// соединение нужно для работы, годится Conn: он подождёт. Здесь же ждать нечего — потолок
// скорости выставится сам при следующем соединении.
func (l *Link) Current() *node.Conn {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.conn
}

// Run держит связь, пока жив контекст.
func (l *Link) Run(ctx context.Context) error {
	defer l.shutdown()

	backoff := minBackoff
	for {
		conn, err := l.dial(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			l.log.Warn("связь не установилась", "err", err, "повтор через", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		// Связь есть — отступ снова минимальный: следующий обрыв может случиться на ровном
		// месте, и заставлять человека ждать пятнадцать секунд из-за прошлой беды незачем.
		backoff = minBackoff
		l.set(conn)
		if l.cfg.OnConnect != nil {
			l.cfg.OnConnect(conn)
		}

		select {
		case <-conn.QUIC().Context().Done():
			l.clear()
			l.notifyGone()
			l.log.Warn("связь потеряна, начинаю гонку заново", "node", conn.Peer().ID)
		case <-ctx.Done():
			l.clear()
			l.notifyGone()
			conn.Close()
			return ctx.Err()
		}
	}
}

func (l *Link) dial(ctx context.Context) (*node.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	return node.DialRace(dialCtx, l.Targets(), l.cfg.TLS, l.cfg.Self, l.cfg.SendMbps, l.log)
}

// Targets отдаёт узлы, среди которых идёт гонка.
func (l *Link) Targets() []node.Target {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.targets
}

// SetTargets меняет список узлов, среди которых идёт гонка.
//
// Живое соединение не рвётся: узел, с которым связь есть, работает — а он и остался в сети,
// раз сам же прислал новый список. Новые узлы вступят в дело при следующей гонке, то есть
// после ближайшего обрыва. Рвать связь ради обновления списка значило бы обрывать человеку
// загрузку из-за события, которого он не заметил бы вовсе.
//
// Пустой список отвергается: остаться без единого узла — это остаться без сети, и лучше
// работать по устаревшему списку, чем ни по какому.
func (l *Link) SetTargets(targets []node.Target) bool {
	if len(targets) == 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.targets = targets
	return true
}

func (l *Link) set(conn *node.Conn) {
	l.mu.Lock()
	l.conn = conn
	// Разбудить всех, кто ждёт соединения. Канал одноразовый, поэтому заводится новый:
	// иначе второй обрыв будить было бы уже нечем.
	close(l.changed)
	l.changed = make(chan struct{})
	l.mu.Unlock()
}

func (l *Link) notifyGone() {
	if l.cfg.OnDisconnect != nil {
		l.cfg.OnDisconnect()
	}
}

func (l *Link) clear() {
	l.mu.Lock()
	l.conn = nil
	l.mu.Unlock()
}

func (l *Link) shutdown() {
	l.mu.Lock()
	l.closed = true
	conn := l.conn
	l.conn = nil
	close(l.changed)
	l.changed = make(chan struct{})
	l.mu.Unlock()

	if conn != nil {
		conn.Close()
	}
}
