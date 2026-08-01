// Package mesh держит связи между узлами.
//
// Узел берёт список соседей из журнала и поднимает к каждому по одному тёплому соединению
// (решение 001). Тёплому — потому что гонка вход→выход идёт по уже установленным связям и
// стоит один RTT вместо целого рукопожатия.
//
// # Курица и яйцо при первом запуске
//
// Узел с пустым журналом не знает ничьих ключей, а приветствие требует ждать конкретный ключ
// собеседника. Разрывается это отпечатком сети: он лежит в конфиге, занесён туда руками, и
// журнал с чужим отпечатком не будет принят, кем бы ни оказался сосед. Поэтому при пустом
// журнале узел знакомится, не проверяя ключ соседа, — но всё, что он у него берёт, проверяется
// подписями и отпечатком. Обратное неверно: сосед нас проверяет всегда, наш ключ уже в его
// журнале, иначе админ нас туда и не добавлял бы.
package mesh

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/jaywehosl/quic-diver/internal/control"
	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/ledger"
	"github.com/jaywehosl/quic-diver/internal/node"
	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/race"
	"github.com/jaywehosl/quic-diver/internal/store"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	// gossipPeriod — как часто узлы сверяются: журнал и расход одним тактом.
	//
	// От этого числа прямо зависит окно, в котором клиент может перебрать лимит, — решение
	// 001 §2 называет порядок в десять секунд.
	gossipPeriod = 10 * time.Second
	// retryMin и retryMax — рамки паузы перед повторной попыткой связи.
	retryMin = 2 * time.Second
	retryMax = 60 * time.Second
	// reviewPeriod — как часто перечитывается список соседей из журнала. Узел, добавленный
	// админом, должен появляться в сети сам, без перезапуска.
	reviewPeriod = 10 * time.Second
)

// Config — что нужно mesh.
type Config struct {
	// Self — кем узел представляется соседям.
	Self hello.Identity
	// Store — журнал: и список соседей, и предмет обмена.
	Store *store.Store
	// Bootstrap — адреса для первого знакомства, когда журнал ещё пуст.
	Bootstrap []string
	// Ledger — динамическая база: расход и сессии. Пустая означает, что узел ничего не
	// считает и ни с кем не сверяется.
	Ledger *ledger.Ledger
	// TLS — с чем идти к соседям. Пустой означает проверку по системным корням.
	TLS *tls.Config
	// Log — куда писать.
	Log *slog.Logger
}

// Mesh поддерживает связи с соседями.
type Mesh struct {
	cfg    Config
	log    *slog.Logger
	runner *race.Runner

	mu    sync.Mutex
	links map[string]*link

	liveMu    sync.RWMutex
	liveLinks map[string]*live
}

// link — одна связь с соседом.
type link struct {
	nodeID string
	cancel context.CancelFunc
}

// meshMbps — потолок BRUTAL на участке узел↔узел (решение 006).
//
// Берётся из журнала на каждый набор, а не запоминается при старте: администратор меняет
// число записью, и оно должно действовать со следующей связи, без перезапуска узла.
func (m *Mesh) meshMbps() int {
	return m.cfg.Store.State().Settings().BrutalMeshMbps
}

// New собирает mesh.
func New(cfg Config) (*Mesh, error) {
	if cfg.Store == nil {
		return nil, errors.New("mesh: не задан журнал")
	}
	if cfg.Self.Signer == nil {
		return nil, errors.New("mesh: не задан ключ узла")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Mesh{
		cfg:       cfg,
		log:       cfg.Log,
		runner:    race.NewRunner(),
		links:     make(map[string]*link),
		liveLinks: make(map[string]*live),
	}, nil
}

// Run поднимает связи и держит их, пока жив контекст.
func (m *Mesh) Run(ctx context.Context) {
	if m.cfg.Store.State().Genesis().IsZero() {
		m.bootstrap(ctx)
	}

	ticker := time.NewTicker(reviewPeriod)
	defer ticker.Stop()

	m.review(ctx)
	for {
		select {
		case <-ctx.Done():
			m.closeAll()
			return
		case <-ticker.C:
			m.review(ctx)
		}
	}
}

// bootstrap добывает журнал у первого попавшегося соседа из конфига.
//
// Ключ соседа здесь не проверяется — его неоткуда взять. Защита в другом: журнал подписан, а
// отпечаток сети записан у нас в конфиге, поэтому подсунуть свою сеть посторонний не может.
func (m *Mesh) bootstrap(ctx context.Context) {
	for _, addr := range m.cfg.Bootstrap {
		select {
		case <-ctx.Done():
			return
		default:
		}

		m.log.Info("знакомство с сетью", "peer", addr)
		if err := m.exchangeOnce(ctx, addr, nil); err != nil {
			m.log.Warn("знакомство не вышло", "peer", addr, "err", err)
			continue
		}
		if !m.cfg.Store.State().Genesis().IsZero() {
			state := m.cfg.Store.State()
			m.log.Info("сеть получена",
				"network", state.Network(),
				"genesis", state.Genesis().String(),
				"nodes", len(state.Nodes()))
			return
		}
	}
}

// review сверяет список соседей из журнала с поднятыми связями.
func (m *Mesh) review(ctx context.Context) {
	state := m.cfg.Store.State()
	want := make(map[string]oplog.Node)
	for _, n := range state.Nodes() {
		if n.ID == m.cfg.Self.ID {
			continue
		}
		want[n.ID] = n
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Узел, выведенный из сети, теряет связь сразу же: отзыв должен действовать, а не ждать
	// следующего обрыва.
	for id, l := range m.links {
		if _, ok := want[id]; !ok {
			m.log.Info("узел выбыл из сети, связь закрывается", "node", id)
			l.cancel()
			delete(m.links, id)
		}
	}

	for id, n := range want {
		if _, ok := m.links[id]; ok {
			continue
		}
		linkCtx, cancel := context.WithCancel(ctx)
		m.links[id] = &link{nodeID: id, cancel: cancel}
		go m.keep(linkCtx, n)
	}
}

// keep держит связь с одним соседом, поднимая её заново после обрыва.
func (m *Mesh) keep(ctx context.Context, n oplog.Node) {
	delay := retryMin
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := m.serve(ctx, n)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if isPolite(err) {
				// Сосед закрылся штатно — перезапуск, уход из сети, смена версии.
				// Кричать об этом значит утопить в шуме настоящие обрывы.
				m.log.Debug("связь с соседом закрыта", "node", n.ID)
			} else {
				m.log.Warn("связь с соседом оборвалась", "node", n.ID, "err", err)
			}
		}

		// Пауза растёт до потолка, но с разбросом: без него узлы, потерявшие общего
		// соседа, будут ломиться к нему в одну и ту же секунду.
		jitter := time.Duration(rand.Int64N(int64(delay / 2)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay/2 + jitter):
		}
		if delay < retryMax {
			delay *= 2
		}
	}
}

// serve поднимает связь и обменивается журналом, пока она жива.
//
// Адреса перебираются по очереди: у узла их обычно два, v4 и v6, и недоступность одного не
// повод считать соседа мёртвым.
func (m *Mesh) serve(ctx context.Context, n oplog.Node) error {
	for _, addr := range n.Endpoints {
		err := m.exchangeLoop(ctx, addr, n)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			return nil
		}
		m.log.Debug("адрес соседа не отозвался", "node", n.ID, "addr", addr, "err", err)
	}
	return fmt.Errorf("ни один адрес узла %s не отозвался", n.ID)
}

// exchangeLoop живёт на установленной связи: сверяет журналы по кругу.
func (m *Mesh) exchangeLoop(ctx context.Context, addr string, n oplog.Node) error {
	conn, err := m.dial(ctx, addr, n.Domain, n.PublicKey)
	if err != nil {
		return err
	}
	defer conn.Close()

	m.log.Info("связь с соседом установлена", "node", n.ID, "addr", addr)

	// Канал гонки поднимается сразу же и отдельным потоком: датаграммы привязаны к своему
	// запросу, а поток журнала занят обменом, и вклиниваться в его такт нельзя.
	channel, err := conn.OpenRace(ctx, n.Domain)
	if err != nil {
		return fmt.Errorf("канал гонки к %s: %w", n.ID, err)
	}
	defer channel.Close()

	l := &live{node: n, conn: conn, channel: channel}
	forget := m.addLive(l)
	defer forget()

	// Отклики соседа приходят по этому же каналу.
	go m.readRace(ctx, l)

	ticker := time.NewTicker(gossipPeriod)
	defer ticker.Stop()

	for {
		if err := m.exchange(conn.Stream(), n.ID); err != nil {
			// Рвём сами: обмен соединением не владеет, а собеседник, отвергнувший его,
			// может ждать нашей записи.
			return err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// exchange — один такт обмена с соседом: журнал, затем расход.
//
// Оба всегда вместе и всегда в этом порядке. Разный ритм у двух половин был бы ошибкой: обмен
// симметричный, обе стороны и пишут, и читают, и стоит тактам разъехаться — одна сторона
// присылает журнал, когда другая ждёт расход, и связь рвётся на «ждали одно, пришло другое».
//
// Журнал при этом почти ничего не стоит: сверка начинается с обмена счётчиками, и когда
// расходиться нечему, дальше этого не идёт.
func (m *Mesh) exchange(stream io.ReadWriter, peer string) error {
	res, err := control.Sync(stream, m.cfg.Store)
	if err != nil {
		return fmt.Errorf("обмен с %s: %w", peer, err)
	}
	if res.Sent > 0 || res.Received > 0 {
		m.log.Info("журналы сверены", "node", peer, "sent", res.Sent, "received", res.Received)
	}

	if m.cfg.Ledger == nil {
		return nil
	}
	if err := control.ExchangeUsage(stream, m.cfg.Ledger); err != nil {
		return fmt.Errorf("обмен расходом с %s: %w", peer, err)
	}
	return nil
}

// readRace разбирает всё, что приходит по каналу гонки от соседа.
//
// Сюда попадают и отклики на наши предложения, и предложения соседа: канал двусторонний,
// а роли у узла могут быть обе сразу.
func (m *Mesh) readRace(ctx context.Context, l *live) {
	for {
		msg, err := l.channel.Receive(ctx)
		if err != nil {
			return
		}
		answer, err := m.OnRace(l.node.ID, msg)
		if err != nil {
			m.log.Debug("сообщение гонки не понято", "node", l.node.ID, "err", err)
			continue
		}
		if answer == nil {
			continue
		}
		if err := l.channel.Send(answer); err != nil {
			return
		}
	}
}

// exchangeOnce поднимает связь, сверяет журналы один раз и уходит. Нужен для знакомства.
func (m *Mesh) exchangeOnce(ctx context.Context, addr string, expect oplog.PublicKey) error {
	// При знакомстве в конфиге стоит имя, а не адрес, поэтому имя берём из него же.
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	conn, err := m.dial(ctx, addr, host, expect)
	if err != nil {
		return err
	}
	defer conn.Close()

	res, err := control.Sync(conn.Stream(), m.cfg.Store)
	if err != nil {
		return err
	}
	m.log.Debug("журналы сверены", "peer", addr, "sent", res.Sent, "received", res.Received)
	return nil
}

// dial поднимает соединение и проходит приветствие.
//
// serverName обязателен: к узлу ходят по литералу адреса, а сертификат выписан на имя.
// Без него рукопожатие падает на стороне соседа, и в логе видно лишь глухое
// «CRYPTO_ERROR: tls: internal error» — узел не может выбрать сертификат, не зная, кого у
// него спрашивают.
func (m *Mesh) dial(ctx context.Context, addr, serverName string, expect oplog.PublicKey) (*node.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var tlsConf *tls.Config
	if m.cfg.TLS != nil {
		tlsConf = m.cfg.TLS.Clone()
	} else {
		tlsConf = &tls.Config{}
	}
	tlsConf.ServerName = serverName

	conn, err := node.Dial(dialCtx, addr, tlsConf, m.cfg.Self, expect, m.meshMbps())
	if err != nil {
		return nil, err
	}
	conn.SetLog(m.log)
	return conn, nil
}

// isPolite отличает штатное закрытие от настоящего обрыва.
func isPolite(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return true
	}
	var h3 *http3.Error
	if errors.As(err, &h3) {
		return h3.ErrorCode == http3.ErrCodeNoError || h3.ErrorCode == http3.ErrCodeRequestCanceled
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return appErr.ErrorCode == 0
	}
	return false
}

func (m *Mesh) closeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, l := range m.links {
		l.cancel()
		delete(m.links, id)
	}
}

// Accept обслуживает связь, поднятую соседом.
//
// Такт задаёт тот, кто связь поднял, — здесь паузы нет. Иначе обе стороны отсчитывали бы
// свои тридцать секунд от разных моментов, фазы бы разъехались, и каждая начала бы читать
// кадры чужого круга обмена. Обмен симметричен по содержанию, но ведущий у него один.
func (m *Mesh) Accept(ctx context.Context, peer *hello.Peer, stream io.ReadWriter) error {
	m.log.Info("сосед пришёл сам", "node", peer.ID)

	// Ведущий в этой паре — сосед: он решает, когда сверяться, а мы отвечаем тем же и в том
	// же порядке. Своего ритма здесь нет намеренно — чтение и так ждёт, пока сосед начнёт.
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := m.exchange(stream, peer.ID); err != nil {
			return err
		}
	}
}
