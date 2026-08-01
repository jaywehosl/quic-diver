package node

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/hwid"
	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/quicx"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Conn — установленное и опознанное соединение с узлом.
type Conn struct {
	quic   *quic.Conn
	http3  *http3.ClientConn
	stream io.ReadWriter
	body   io.ReadCloser
	pipe   *io.PipeWriter
	peer   *hello.Peer
	// authority — имя узла для :authority. Обычному CONNECT оно не нужно (там в
	// :authority едет сама цель), а расширенному нужно: цель у него в пути, а в
	// :authority — тот, кого просят.
	authority string
	log       *slog.Logger
}

// SetLog задаёт, куда соединение пишет о своих бедах. Без него оно молчит.
func (c *Conn) SetLog(log *slog.Logger) { c.log = log }

// Peer — кем оказался узел на том конце.
func (c *Conn) Peer() *hello.Peer { return c.peer }

// Stream — управляющий поток. Читать и писать можно одновременно.
func (c *Conn) Stream() io.ReadWriter { return c.stream }

// QUIC отдаёт нижележащее соединение — оно понадобится для потоков трафика.
func (c *Conn) QUIC() *quic.Conn { return c.quic }

// Close закрывает соединение.
func (c *Conn) Close() error {
	if c.pipe != nil {
		c.pipe.Close()
	}
	if c.body != nil {
		c.body.Close()
	}
	return c.quic.CloseWithError(0, "")
}

// Dial поднимает соединение с узлом и проходит приветствие.
//
// Соединение поднимается вручную, а не через http.Client, по необходимости: приветствие
// подписывает привязку к TLS-сессии, а до неё добраться можно только имея на руках само
// соединение. Заодно это ровно тот путь, которым позже пойдёт и трафик.
// sendMbps — потолок BRUTAL для своей отправки (решение 006). Ноль означает обычный Cubic.
func Dial(
	ctx context.Context,
	addr string,
	tlsConf *tls.Config,
	self hello.Identity,
	expect oplog.PublicKey,
	sendMbps int,
) (*Conn, error) {
	conf := tlsConf.Clone()
	conf.NextProtos = []string{quicx.ALPN}

	qc, err := quic.DialAddr(ctx, addr, conf, quicx.ClientConfig(sendMbps))
	if err != nil {
		return nil, fmt.Errorf("node: соединение с %s: %w", addr, err)
	}

	// К узлу ходят по адресу, а сертификат выписан на имя — значит и :authority должен нести
	// имя, а не адрес. Узлы соединяются между собой по литералам (клиенту нужны литералы,
	// чтобы поднять исключения маршрутизации до включения туннеля), поэтому имя приходит
	// отдельно, в ServerName.
	authority := addr
	if conf.ServerName != "" {
		authority = conf.ServerName
	}

	c, err := greet(ctx, qc, authority, self, expect)
	if err != nil {
		qc.CloseWithError(0, "")
		return nil, err
	}
	return c, nil
}

// Greet проходит приветствие поверх уже поднятого QUIC-соединения.
//
// Отдельно от Dial это нужно там, где соединение пришло со стороны: победитель гонки, узел,
// поднявший связь заранее, соединение из пула.
func Greet(
	ctx context.Context,
	qc *quic.Conn,
	authority string,
	self hello.Identity,
	expect oplog.PublicKey,
) (*Conn, error) {
	return greet(ctx, qc, authority, self, expect)
}

func greet(
	ctx context.Context,
	qc *quic.Conn,
	authority string,
	self hello.Identity,
	expect oplog.PublicKey,
) (*Conn, error) {
	binding, err := quicx.Binding(qc.ConnectionState().TLS)
	if err != nil {
		return nil, fmt.Errorf("node: %w", err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	cc := tr.NewClientConn(qc)

	// Тело запроса — канал: длина заранее неизвестна, писать в него можно сколько угодно
	// долго. Через OpenRequestStream этого не добиться: там тело обязано быть пустым, а
	// пустому телу клиент проставляет content-length: 0, после чего первый же байт
	// приветствия сервер считает лишним и рвёт поток на H3_MESSAGE_ERROR.
	pr, pw := io.Pipe()

	// Управляющий поток живёт дольше, чем вызов Dial: ctx здесь отмеряет установление
	// соединения, и обычно у него есть срок. Привязать к нему запрос значит убить поток
	// сразу после возврата — ровно это и происходило: H3_REQUEST_CANCELLED через миг после
	// успешного приветствия. Закрывается поток теперь только через Conn.Close.
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx),
		http.MethodPost, "https://"+authority+ControlPath, pr)
	if err != nil {
		return nil, fmt.Errorf("node: сборка запроса: %w", err)
	}
	req.ContentLength = -1
	// Устройство называет себя здесь, а не в приветствии: считать по нему нужно только
	// собственный лимит клиента, и подписи для этого не требуется (см. internal/hwid).
	if device := hwid.Get(); device != "" {
		req.Header.Set(DeviceHeader, device)
	}

	type roundTrip struct {
		resp *http.Response
		err  error
	}
	done := make(chan roundTrip, 1)
	go func() {
		resp, err := cc.RoundTrip(req)
		done <- roundTrip{resp, err}
	}()

	now := time.Now()
	if err := hello.Send(pw, binding, self, now); err != nil {
		pw.CloseWithError(err)
		return nil, err
	}

	rt := <-done
	if rt.err != nil {
		pw.Close()
		return nil, fmt.Errorf("node: управляющий запрос: %w", rt.err)
	}
	// Узел, который нас не признал, отвечает обычной страницей — ровно как постороннему.
	if rt.resp.StatusCode != http.StatusOK {
		pw.Close()
		rt.resp.Body.Close()
		return nil, fmt.Errorf("%w: узел ответил %s", hello.ErrUnknownPeer, rt.resp.Status)
	}

	// Пустой ожидаемый ключ — это первое знакомство узла с сетью: журнала ещё нет, сверять
	// подпись собеседника не с чем. Подробности и границы этого случая — в
	// hello.ReceiveUnchecked.
	var peer *hello.Peer
	if len(expect) == 0 {
		peer, err = hello.ReceiveUnchecked(rt.resp.Body, now)
	} else {
		peer, err = hello.Receive(rt.resp.Body, binding, expect, now)
	}
	if err != nil {
		pw.Close()
		rt.resp.Body.Close()
		return nil, err
	}
	return &Conn{
		quic:      qc,
		http3:     cc,
		stream:    &duplex{r: rt.resp.Body, w: pw},
		body:      rt.resp.Body,
		pipe:      pw,
		peer:      peer,
		authority: authority,
	}, nil
}
