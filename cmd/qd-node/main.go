// Команда qd-node — узел сети.
//
// Узел слушает три адреса и все три ведут себя как обычный сайт: :80 отдаёт перенаправление
// на https и отвечает на проверку владения доменом, TCP:443 отдаёт заглушку по HTTP/1.1 и
// HTTP/2, UDP:443 — то же самое по HTTP/3, и только там же, внутри соединения, живёт
// управляющий канал для тех, кто предъявил подпись.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jaywehosl/quic-diver/internal/certs"
	"github.com/jaywehosl/quic-diver/internal/config"
	"github.com/jaywehosl/quic-diver/internal/control"
	"github.com/jaywehosl/quic-diver/internal/decoy"
	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/ledger"
	"github.com/jaywehosl/quic-diver/internal/mesh"
	"github.com/jaywehosl/quic-diver/internal/node"
	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/store"
)

func main() {
	configPath := flag.String("config", "/etc/qdiver/node.toml", "путь к файлу настроек")
	showKey := flag.Bool("show-key", false, "напечатать публичный ключ узла и выйти")
	importPath := flag.String("import", "", "влить журнал из файла и выйти")
	deployKey := flag.String("deploy", "", "разложить настройки по ключу развёртывания и выйти")
	showUsage := flag.Bool("usage", false, "напечатать расход, посчитанный этим узлом, и выйти")
	flag.Parse()

	if *showUsage {
		if err := printUsage(*configPath); err != nil {
			fmt.Fprintln(os.Stderr, "qd-node:", err)
			os.Exit(1)
		}
		return
	}
	// Раскладка настроек идёт до всего остального: конфига в этот момент ещё нет, и обычный
	// путь запуска упал бы на его чтении.
	if *deployKey != "" {
		if err := deployNode(*deployKey, *configPath); err != nil {
			fmt.Fprintln(os.Stderr, "qd-node:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(*configPath, *showKey, *importPath); err != nil {
		fmt.Fprintln(os.Stderr, "qd-node:", err)
		os.Exit(1)
	}
}

func run(configPath string, showKey bool, importPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if err := cfg.EnsureDirs(); err != nil {
		return err
	}

	log := newLogger(cfg.LogLevel)

	signer, created, err := loadOrCreateKey(cfg.KeyFile)
	if err != nil {
		return err
	}
	if created {
		log.Info("создан ключ узла", "file", cfg.KeyFile, "key_id", signer.KeyID().String())
	}
	if showKey {
		// Код печатается рядом с ключом: его человек переносит в приложение, чтобы то
		// убедилось, что говорит с этим узлом, а не с тем, кто перехватил домен
		// (см. internal/node/code.go).
		fmt.Printf("node_id=%s\npublic_key=%x\ncode=%s\n",
			cfg.ID, signer.Public(), node.Code(oplog.PublicKey(signer.Public())))
		return nil
	}

	fingerprint, err := cfg.Fingerprint()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.StorePath(), fingerprint)
	if err != nil {
		return err
	}
	defer st.Close()

	if importPath != "" {
		return importLog(st, importPath)
	}

	if st.State().Genesis().IsZero() {
		// Узел, ещё не получивший журнала, работать как узел не может — но сайтом он уже
		// является, и это ровно то, чем он должен выглядеть до включения в сеть.
		log.Warn("журнал пуст: узел отдаёт только заглушку и ждёт включения в сеть")
	} else {
		log.Info("журнал загружен",
			"network", st.State().Network(),
			"genesis", st.State().Genesis().String(),
			"clients", len(st.State().Clients()),
			"nodes", len(st.State().Nodes()))
	}

	cm, err := certs.New(certs.Options{
		Domain:    cfg.Domain,
		CacheDir:  cfg.CertDir(),
		Email:     cfg.ACMEEmail,
		Directory: cfg.ACMEDirectory,
	})
	if err != nil {
		return err
	}

	self := hello.Identity{Role: hello.RoleNode, ID: cfg.ID, Signer: signer}

	// Динамическая база: расход и живые сессии. Живёт в памяти и собирается заново после
	// перезапуска — узлы разнесут друг другу то, что помнят (решение 001 §2).
	events := ledger.New(ledger.Config{Self: cfg.ID})
	books := newAccounting(events, st, log)
	// Свой счётчик поднимается с диска: лимит за месяц обязан пережить перезапуск узла,
	// иначе он не лимит, а пожелание.
	books.restore()

	mesh, err := mesh.New(mesh.Config{
		Self:      self,
		Store:     st,
		Bootstrap: cfg.Peers,
		Ledger:    events,
		// Пока журнала нет, потолок между узлами берётся из файла настроек: он приехал
		// ключом развёртывания. С приходом журнала верх берут числа из него.
		FallbackMeshMbps: cfg.BrutalMeshMbps,
		Log:              log,
	})
	if err != nil {
		return err
	}

	// Имена разрешает узел, и делает это своим резолвером: с кешем, своими адресами и
	// переопределением времени жизни. Настройки приезжают журналом и меняются на лету.
	resolver := newResolver(st, log)

	site := decoy.New()
	n, err := node.New(node.Config{
		Resolver:  resolver,
		Addr:      cfg.Listen,
		TLS:       cm.TLSConfigQUIC(),
		Identity:  self,
		Directory: hello.StateDirectory{State: st.State()},
		Decoy:     site,
		// Первый залив журнала по сети: пустому узлу опознать пришедшего нечем, и круг
		// разрывает отпечаток сети из конфига (см. internal/node/bootstrap.go).
		Import: bootstrapImporter{st: st},
		// Пока узел не в сети, он называет свой ключ каждому, кто спросит. Иначе запись об
		// узле не написать: подписывает её владелец у себя, а ключ рождается здесь.
		Introduce: func() node.Introduction {
			return node.Introduction{
				ID:        cfg.ID,
				Domain:    cfg.Domain,
				PublicKey: oplog.PublicKey(signer.Public()),
			}
		},
		Control: controlHandler(log, mesh, st, books),
		OnRace:  mesh.OnRace,
		Exits:   mesh,
		// Узел шлёт клиенту «вниз»: столько, сколько тот в состоянии принять (решение 006).
		SendMbps: brutalDown(cfg, st),
		Meter:    books,
		Sessions: books,
		Log:      log,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go mesh.Run(ctx)
	go watchDNS(ctx, st, resolver, log)
	go books.sweep(ctx)

	// :80 — проверка владения доменом и перенаправление, как у любого сайта.
	acmeSrv := &http.Server{
		Addr:              cfg.ListenACME,
		Handler:           cm.HTTPHandler(redirectToHTTPS(cfg.Domain)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go serve(log, "acme/redirect", cfg.ListenACME, acmeSrv.ListenAndServe)

	// TCP:443 — заглушка по HTTP/1.1 и HTTP/2. Она обязана быть: сайт, живущий только по
	// HTTP/3, встречается куда реже, чем обычный, и уже этим выделяется.
	tcpSrv := &http.Server{
		Addr:              cfg.ListenTCP,
		Handler:           altSvc(site, cfg.Listen),
		TLSConfig:         cm.TLSConfigTCP(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go serve(log, "https", cfg.ListenTCP, func() error { return tcpSrv.ListenAndServeTLS("", "") })

	go func() {
		if err := cm.Warm(); err != nil {
			log.Error("сертификат не получен", "err", err)
			return
		}
		log.Info("сертификат получен", "domain", cfg.Domain)
	}()

	go serve(log, "quic", cfg.Listen, n.ListenAndServe)

	// Печатаются действующие числа, а не журнальные: пока журнала нет, работают те, что
	// приехали ключом развёртывания, и человеку важно видеть именно их.
	log.Info("узел поднят", "id", cfg.ID, "domain", cfg.Domain,
		"quic", cfg.Listen, "https", cfg.ListenTCP, "acme", cfg.ListenACME,
		"brutal_вниз_мбит", brutalDown(cfg, st), "brutal_между_узлами_мбит", brutalMesh(cfg, st))

	<-ctx.Done()
	log.Info("остановка")

	// Расход сохраняется здесь, а не только в подметальщике: тот живёт горутиной и по отмене
	// контекста бежит к тому же save, но успеет ли он до возврата из main — не обещано никем.
	// Посчитанное за последние секунды дороже одной лишней записи на диск.
	books.save()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = acmeSrv.Shutdown(shutdownCtx)
	_ = tcpSrv.Shutdown(shutdownCtx)

	// Close у HTTP/3 ждёт закрытия всех соединений и не имеет своего срока. А соединения
	// держат прокси-потоки: копирование байтов туда-обратно про контекст ничего не знает и
	// кончится только вместе с внешним соединением. Пока на узле сидит хоть один клиент,
	// ожидание вечно — узел висел до systemd-таймаута и добивался SIGKILL.
	//
	// Ждём недолго и уходим. Оборванный поток здесь не потеря: клиент переоткроет его гонкой,
	// это его обычный путь при смене узла. А вот SIGKILL — потеря настоящая: расход,
	// посчитанный после последнего сохранения, пропадает вместе с процессом.
	closed := make(chan error, 1)
	go func() { closed <- n.Close() }()

	select {
	case err := <-closed:
		return err
	case <-time.After(shutdownGrace):
		log.Warn("соединения не закрылись за отведённое время, ухожу", "срок", shutdownGrace)
		return nil
	}
}

// shutdownGrace — сколько ждать закрытия соединений при остановке.
//
// Пяти секунд хватает, чтобы разошлись те, кто действительно закрывается: связи с соседями и
// управляющие каналы уходят по отмене контекста мгновенно. Всё, что не уложилось, — это
// прокси-потоки с живым трафиком, и ждать их можно бесконечно.
const shutdownGrace = 5 * time.Second

// importLog вливает журнал из файла.
//
// Каждая запись проходит те же проверки, что и пришедшая по сети: подпись, права, место в
// последовательности. Файл, собранный кем угодно, ничего не даст, кроме отказа, — поэтому
// доставлять журнал можно любым способом, хоть флешкой.
func importLog(st *store.Store, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	n, err := st.Import(f)
	if err != nil {
		return fmt.Errorf("влито записей %d, дальше ошибка: %w", n, err)
	}
	state := st.State()
	fmt.Printf("влито записей: %d\nсеть: %s\nотпечаток: %s\nузлов: %d, клиентов: %d\n",
		n, state.Network(), state.Genesis(), len(state.Nodes()), len(state.Clients()))
	return nil
}

func serve(log *slog.Logger, what, addr string, fn func() error) {
	if err := fn(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("слушатель остановлен", "what", what, "addr", addr, "err", err)
	}
}

// controlHandler разводит опознанных по назначению.
func controlHandler(log *slog.Logger, m *mesh.Mesh, st *store.Store, books *accounting) node.Control {
	return func(ctx context.Context, peer *hello.Peer, stream io.ReadWriter) error {
		switch peer.Role {
		case hello.RoleNode:
			// Сосед пришёл сам: обмениваемся журналом, ведущим в этой паре будет он.
			return m.Accept(ctx, peer, stream)

		case hello.RoleAdmin:
			// Администратор получает не выжимку, а журнал целиком, и не в одну сторону, а
			// сверкой — тем же обменом, каким сверяются узлы между собой (решение 007).
			//
			// Целиком, а не выжимкой, потому что управлять сетью, не видя её записей, нельзя:
			// клиенты, лимиты, ключи, узлы — всё это и есть журнал. Опасения решения 005 о том,
			// что журнал нельзя раздавать, касались клиентов; администратор и так знает всё,
			// что там написано, — он это и писал.
			//
			// Сверкой, а не отдачей, потому что записи ходят в обе стороны: администратор
			// присылает то, что подписал у себя, узел применяет и разносит соседям.
			return adminSync(ctx, log, st, peer, stream)

		default:
			// Клиент. Ему уезжает выжимка из журнала — правила, параметры сети, узлы, — и
			// уезжает заново на каждое изменение (решение 005). Журнал целиком клиенту не
			// отдаётся: в нём записи обо всех остальных клиентах сети.
			log.Info("управляющий поток открыт", "role", peer.Role.String(), "id", peer.ID)
			err := control.ServeSnapshots(ctx, stream, st, peer.ID, books.usageOf)
			if err != nil && ctx.Err() == nil {
				log.Debug("снапшоты клиенту прекратились", "id", peer.ID, "err", err)
			}
			return err
		}
	}
}

// bootstrapImporter даёт узлу принять первый залив журнала.
//
// Тонкая обёртка вокруг хранилища: пакет node не должен знать про store, а проверку отпечатка
// хранилище и так делает при каждом Import — тем же кодом, что и при заливе файлом.
type bootstrapImporter struct{ st *store.Store }

func (b bootstrapImporter) Genesis() oplog.Fingerprint { return b.st.State().Genesis() }

func (b bootstrapImporter) Import(r io.Reader) (int, error) { return b.st.Import(r) }

// adminSync держит сверку журналов с администратором, пока жива связь.
//
// Такт задаёт администратор: он открыл поток, он и решает, когда сверяться. Узел отвечает на
// каждый заход и ждёт следующего — своего таймера здесь нет, иначе две стороны отсчитывали бы
// паузы по отдельности и рано или поздно разъехались бы (та же беда, что была между узлами).
func adminSync(ctx context.Context, log *slog.Logger, st *store.Store, peer *hello.Peer, stream io.ReadWriter) error {
	log.Info("администратор на связи", "key", peer.ID)

	for ctx.Err() == nil {
		res, err := control.Sync(stream, st)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Отказ по правам — не поломка узла, а обычный ответ «тебе это не положено».
			// Причину администратор уже получил кадром отказа; здесь она записывается затем,
			// чтобы владелец сети мог потом посмотреть, кто и куда лез.
			if errors.Is(err, oplog.ErrForbidden) || errors.Is(err, oplog.ErrRevokedKey) {
				log.Warn("записи администратора отклонены",
					"key", peer.ID, "причина", err)
				return nil
			}
			return fmt.Errorf("сверка с администратором %s: %w", peer.ID, err)
		}
		if res.Sent > 0 || res.Received > 0 {
			log.Info("журнал сверен с администратором",
				"key", peer.ID, "отдано", res.Sent, "принято", res.Received)
		}
	}
	return nil
}

// redirectToHTTPS отвечает так же, как ответил бы любой сайт с сертификатом.
func redirectToHTTPS(domain string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + domain + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

// altSvc объявляет поддержку HTTP/3 — так делает всякий сайт, который его умеет.
//
// Скрывать объявление было бы ошибкой: сайт, отвечающий по HTTP/3 и при этом молчащий о нём
// в Alt-Svc, встречается реже, чем обычный, и потому заметнее.
func altSvc(next http.Handler, quicAddr string) http.Handler {
	_, port, err := net.SplitHostPort(quicAddr)
	if err != nil || port == "" {
		port = "443"
	}
	value := fmt.Sprintf(`h3=":%s"; ma=86400`, port)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", value)
		next.ServeHTTP(w, r)
	})
}

// loadOrCreateKey читает ключ узла, а если его ещё нет — создаёт.
func loadOrCreateKey(path string) (*oplog.MemorySigner, bool, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(raw) != ed25519.PrivateKeySize {
			return nil, false, fmt.Errorf("qd-node: файл ключа %s повреждён: %d байт", path, len(raw))
		}
		s, err := oplog.NewMemorySigner(ed25519.PrivateKey(raw))
		return s, false, err

	case errors.Is(err, os.ErrNotExist):
		s, err := oplog.GenerateSigner()
		if err != nil {
			return nil, false, err
		}
		// 0600: приватный ключ узла — то единственное, чем узел доказывает, что он свой.
		if err := os.WriteFile(path, s.Private(), 0o600); err != nil {
			return nil, false, fmt.Errorf("qd-node: запись ключа: %w", err)
		}
		return s, true, nil

	default:
		return nil, false, fmt.Errorf("qd-node: чтение ключа: %w", err)
	}
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
