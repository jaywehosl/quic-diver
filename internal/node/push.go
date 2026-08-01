package node

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/jaywehosl/quic-diver/internal/quicx"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Introduce спрашивает узел, кто он.
//
// Отвечает только узел, ещё не включённый в сеть: дальше этот путь закрывается, и ответом
// становится обычная страница. Ходит без приветствия — проходить его не с чем, обе стороны
// друг о друге ничего не знают.
func Introduce(ctx context.Context, addr string, tlsConf *tls.Config) (Introduction, error) {
	conf := tlsConf.Clone()
	conf.NextProtos = []string{quicx.ALPN}

	qc, err := quic.DialAddr(ctx, addr, conf, quicx.ClientConfig(0))
	if err != nil {
		return Introduction{}, fmt.Errorf("node: соединение с %s: %w", addr, err)
	}
	defer qc.CloseWithError(0, "")

	authority := addr
	if conf.ServerName != "" {
		authority = conf.ServerName
	}

	tr := &http3.Transport{}
	cc := tr.NewClientConn(qc)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+authority+BootstrapPath, nil)
	if err != nil {
		return Introduction{}, fmt.Errorf("node: сборка запроса: %w", err)
	}

	resp, err := cc.RoundTrip(req)
	if err != nil {
		return Introduction{}, fmt.Errorf("node: запрос к узлу: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Introduction{}, fmt.Errorf("node: узел не представился (%s); скорее всего он уже в сети", resp.Status)
	}

	var intro Introduction
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxIntroduction)).Decode(&intro); err != nil {
		return Introduction{}, fmt.Errorf("node: разбор представления: %w", err)
	}
	if len(intro.PublicKey) != ed25519.PublicKeySize {
		return Introduction{}, fmt.Errorf("node: узел назвал ключ длиной %d байт вместо %d",
			len(intro.PublicKey), ed25519.PublicKeySize)
	}
	if intro.Domain == "" {
		return Introduction{}, fmt.Errorf("node: узел не назвал домена")
	}
	return intro, nil
}

// maxIntroduction ограничивает представление: имя, домен и ключ укладываются в сотни байт.
const maxIntroduction = 4 << 10

// PushLog заливает журнал в узел, который ещё не в сети.
//
// Ходит без приветствия — его не с чем проходить: узел ещё не знает ни одного ключа, а мы не
// знаем его. Одна сторона проверяет отпечаток сети, другая — сертификат домена; больше здесь
// проверять нечем и не нужно (решение 007 §3.3).
//
// Ответ намеренно скупой: узел, уже получивший журнал, отвечает как на любой неизвестный путь.
// Отличить «залив не нужен» от «залив не принят» снаружи нельзя, и это свойство, а не недочёт.
func PushLog(ctx context.Context, addr string, tlsConf *tls.Config, journal io.Reader) error {
	conf := tlsConf.Clone()
	conf.NextProtos = []string{quicx.ALPN}

	qc, err := quic.DialAddr(ctx, addr, conf, quicx.ClientConfig(0))
	if err != nil {
		return fmt.Errorf("node: соединение с %s: %w", addr, err)
	}
	defer qc.CloseWithError(0, "")

	authority := addr
	if conf.ServerName != "" {
		authority = conf.ServerName
	}

	tr := &http3.Transport{}
	cc := tr.NewClientConn(qc)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+authority+BootstrapPath, journal)
	if err != nil {
		return fmt.Errorf("node: сборка запроса: %w", err)
	}

	resp, err := cc.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("node: залив журнала: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("node: узел не принял журнал (%s); либо он уже в сети, либо отпечаток сети у него другой", resp.Status)
	}
	return nil
}
