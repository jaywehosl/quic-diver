package node

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// Stream — поток трафика через узел.
type Stream struct {
	rw   io.ReadWriter
	body io.ReadCloser
	pipe *io.PipeWriter
	via  string
}

// ViaEgress говорит, вышел ли поток через выходной узел.
//
// Когда выхода не нашлось, поток выпускается на входном узле: связь важнее страны. Но клиент
// обязан узнать об этом — иначе он будет считать, что сидит в Варшаве, находясь в Москве.
//
// Имени выходного узла клиенту не сообщают вовсе, см. ExitVia.
func (s *Stream) ViaEgress() bool { return s.via == ExitViaEgress }

func (s *Stream) Read(p []byte) (int, error)  { return s.rw.Read(p) }
func (s *Stream) Write(p []byte) (int, error) { return s.rw.Write(p) }

// Close закрывает поток. Узел, увидев конец записи, закроет и внешнее соединение.
func (s *Stream) Close() error {
	s.pipe.Close()
	return s.body.Close()
}

// CloseWrite закрывает только свою половину: «я всё сказал, но слушаю дальше».
//
// Без этого пересылка через выходной узел встаёт намертво. Клиент дописал запрос и умолк,
// входной узел ждёт ответа от выходного, а выходной ждёт, когда входной договорит, — и оба
// висят до таймаута. Ровно та же полузакрытость есть у TCP, и обходиться без неё нельзя.
func (s *Stream) CloseWrite() error { return s.pipe.Close() }

// Open просит узел открыть соединение с адресом и отдаёт поток к нему.
//
// Это обычный CONNECT по RFC 9114 §4.4 — тот самый метод, которым HTTP-прокси работают
// десятилетиями. Заново здороваться не нужно: узел узнаёт соединение по привязке к
// TLS-сессии, а приветствие прошло на управляющем потоке.
func (c *Conn) Open(ctx context.Context, target string) (*Stream, error) {
	return c.OpenVia(ctx, target, false)
}

// OpenVia просит выпустить поток через выходной узел, если viaExit истинно.
//
// Иначе поток выходит наружу на том узле, к которому подключён клиент. Третьего не дано, и
// какой именно выход достанется потоку, клиент не выбирает — это дело гонки. Через кого он
// вышел на самом деле, сообщается в ответе: запасной путь молчаливым быть не должен.
func (c *Conn) OpenVia(ctx context.Context, target string, viaExit bool) (*Stream, error) {
	return c.OpenFor(ctx, target, viaExit, "")
}

// OpenFor открывает поток, называя, чей это трафик.
//
// Имя клиента ставит входной узел, пересылая поток на выходной: сокет наружу открывает выход,
// ему и считать байты, а клиента он не знает (решение 001 §2). Клиент сам это поле не
// заполняет — от него оно и не принимается.
func (c *Conn) OpenFor(ctx context.Context, target string, viaExit bool, client string) (*Stream, error) {
	pr, pw := io.Pipe()

	// Контекст здесь отмеряет открытие, а поток живёт дольше — как и на управляющем канале.
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx),
		http.MethodConnect, "https://"+target, pr)
	if err != nil {
		pw.Close()
		return nil, fmt.Errorf("node: сборка CONNECT: %w", err)
	}
	req.Host = target
	req.ContentLength = -1
	if viaExit {
		req.Header.Set(ExitHeader, ExitYes)
	}
	if client != "" {
		req.Header.Set(ClientHeader, client)
	}

	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := c.http3.RoundTrip(req)
		done <- result{resp, err}
	}()

	select {
	case <-ctx.Done():
		pw.Close()
		return nil, ctx.Err()
	case rt := <-done:
		if rt.err != nil {
			pw.Close()
			return nil, fmt.Errorf("node: CONNECT %s: %w", target, rt.err)
		}
		if rt.resp.StatusCode != http.StatusOK {
			pw.Close()
			rt.resp.Body.Close()
			return nil, fmt.Errorf("node: узел отказал в %s: %s", target, rt.resp.Status)
		}
		return &Stream{
			rw:   &duplex{r: rt.resp.Body, w: pw},
			body: rt.resp.Body,
			pipe: pw,
			via:  rt.resp.Header.Get(ExitVia),
		}, nil
	}
}
