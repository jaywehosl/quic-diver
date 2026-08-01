package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Гонка рукопожатий: клиент → входные узлы (решение 004 §2).
//
// Клиент обращается ко всем входным узлам сразу и работает с первым, кто **поздоровался**.
// Не с первым, кто поднял TLS: узел, который нас не признал, рукопожатие завершит, а толку
// от него ноль.
//
// Проигравшие закрываются явно. Это прямо оговорено в ТЗ: сигнал о сбросе обязан дойти до
// узла, иначе тот будет держать сессию, горутину и сокет, ожидая продолжения. Молчаливый
// уход означал бы ожидание idle-таймаута на каждом проигравшем узле при каждом подключении.

// Target — узел, к которому стучится гонка.
type Target struct {
	// ID — как узел зовут. Только для журнала.
	ID string
	// Domain — имя из сертификата: идёт в SNI и в :authority.
	Domain string
	// Endpoints — адреса вида host:port. Их тоже несколько, и они тоже участвуют в гонке:
	// у узла бывает и v4, и v6, а рабочим оказывается не всегда тот, что первый в списке.
	Endpoints []string
	// PublicKey — чем узел докажет, что он из нашей сети. TLS этого не покажет: он опирается
	// на публичную PKI, а принадлежность сети видна только по подписи.
	PublicKey oplog.PublicKey
}

// ErrNoTargets означает, что гонке некуда бежать.
var ErrNoTargets = errors.New("node: не задан ни один узел")

// raceResult — чем кончилась одна попытка.
type raceResult struct {
	conn     *Conn
	err      error
	node     string
	endpoint string
}

// DialRace обращается ко всем узлам сразу и возвращает первое опознанное соединение.
func DialRace(
	ctx context.Context,
	targets []Target,
	tlsConf *tls.Config,
	self hello.Identity,
	sendMbps int,
	log *slog.Logger,
) (*Conn, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	type attempt struct {
		node     Target
		endpoint string
	}
	var attempts []attempt
	for _, t := range targets {
		for _, e := range t.Endpoints {
			attempts = append(attempts, attempt{node: t, endpoint: e})
		}
	}
	if len(attempts) == 0 {
		return nil, ErrNoTargets
	}

	// Отмена — то, чем гонка гасит опоздавших. Соединения, успевшие встать до неё,
	// закрываются явно ниже: отмена контекста установленный QUIC не рвёт.
	raceCtx, cancel := context.WithCancel(ctx)
	// Канал вмещает все ответы: горутина опоздавшего должна суметь отчитаться и уйти, даже
	// если её результата уже никто не ждёт.
	results := make(chan raceResult, len(attempts))

	for _, a := range attempts {
		go func(a attempt) {
			conf := tlsConf.Clone()
			// К узлу идут по адресу, а сертификат выписан на имя.
			conf.ServerName = a.node.Domain

			conn, err := Dial(raceCtx, a.endpoint, conf, self, a.node.PublicKey, sendMbps)
			results <- raceResult{conn: conn, err: err, node: a.node.ID, endpoint: a.endpoint}
		}(a)
	}

	var errs []error
	for left := len(attempts); left > 0; left-- {
		r := <-results
		if r.err != nil {
			errs = append(errs, fmt.Errorf("%s (%s): %w", r.node, r.endpoint, r.err))
			continue
		}

		log.Info("гонку выиграл узел", "node", r.node, "addr", r.endpoint, "из", len(attempts))
		// Отмена гасит тех, кто ещё в пути. Тех, кто успел встать, добьёт уборщик:
		// установленное соединение отмена контекста не рвёт.
		cancel()
		go dropLosers(results, left-1, log)
		return r.conn, nil
	}

	cancel()
	return nil, fmt.Errorf("гонка не дала ни одного соединения: %w", errors.Join(errs...))
}

// dropLosers дожидается опоздавших и закрывает их явно.
//
// Ждать их вызывающему незачем, а бросить нельзя: соединение, о котором узел не узнал, что
// оно не нужно, живёт до idle-таймаута и всё это время держит сессию, горутину и сокет.
func dropLosers(results <-chan raceResult, left int, log *slog.Logger) {
	for ; left > 0; left-- {
		r := <-results
		if r.conn != nil {
			log.Debug("опоздавшее соединение закрыто", "node", r.node, "addr", r.endpoint)
			r.conn.Close()
		}
	}
}
