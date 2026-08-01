// Команда qd-probe смотрит на узел снаружи ровно так, как это сделал бы посторонний.
//
// Нужна для того, чтобы проверять узел не по своим ожиданиям, а по тому, что он реально
// отдаёт в сеть: работает ли HTTP/3, чем он отвечает на управляющий путь и отличается ли
// этот ответ от ответа на любой другой адрес.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/node"
	"github.com/jaywehosl/quic-diver/internal/oplog"
	"github.com/jaywehosl/quic-diver/internal/quicx"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	addr := flag.String("addr", "", "адрес узла, например qdiver1.example.com:443")
	insecure := flag.Bool("insecure", false, "не проверять сертификат")
	clientID := flag.String("client-id", "", "идентификатор клиента для проверки приветствия")
	clientKey := flag.String("client-key", "", "приватный ключ клиента в шестнадцатеричном виде")
	nodeKey := flag.String("node-key", "", "ожидаемый публичный ключ узла")
	flag.Parse()

	if *addr == "" {
		fmt.Fprintln(os.Stderr, "qd-probe: не задан -addr")
		os.Exit(2)
	}
	if !strings.Contains(*addr, ":") {
		*addr += ":443"
	}
	host, _, _ := strings.Cut(*addr, ":")

	if err := probe(*addr, host, *insecure); err != nil {
		fmt.Fprintln(os.Stderr, "qd-probe:", err)
		os.Exit(1)
	}

	if *clientID != "" {
		if err := greet(*addr, host, *insecure, *clientID, *clientKey, *nodeKey); err != nil {
			fmt.Fprintln(os.Stderr, "qd-probe: приветствие:", err)
			os.Exit(1)
		}
	}
}

// greet проверяет то, чего посторонний увидеть не может: что свой действительно проходит.
func greet(addr, host string, insecure bool, id, privHex, nodeKeyHex string) error {
	priv, err := hex.DecodeString(privHex)
	if err != nil {
		return fmt.Errorf("ключ клиента: %w", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("ключ клиента должен быть %d байт, получено %d", ed25519.PrivateKeySize, len(priv))
	}
	signer, err := oplog.NewMemorySigner(ed25519.PrivateKey(priv))
	if err != nil {
		return err
	}
	nodePub, err := hex.DecodeString(nodeKeyHex)
	if err != nil {
		return fmt.Errorf("ключ узла: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := node.Dial(ctx, addr,
		&tls.Config{ServerName: host, InsecureSkipVerify: insecure},
		hello.Identity{Role: hello.RoleClient, ID: id, Signer: signer},
		oplog.PublicKey(nodePub),
		0,
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	fmt.Printf("\nприветствие принято: узел %s (%s)\n", conn.Peer().ID, conn.Peer().Role)
	fmt.Println("управляющий поток открыт")
	return nil
}

func probe(addr, host string, insecure bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	tlsConf := &tls.Config{ServerName: host, InsecureSkipVerify: insecure, NextProtos: []string{quicx.ALPN}}
	qc, err := quic.DialAddr(ctx, addr, tlsConf, quicx.ClientConfig(0))
	if err != nil {
		return fmt.Errorf("QUIC не поднялся: %w", err)
	}
	defer qc.CloseWithError(0, "")

	state := qc.ConnectionState()
	fmt.Printf("QUIC установлен: версия %s, ALPN %q\n", state.Version, state.TLS.NegotiatedProtocol)
	if len(state.TLS.PeerCertificates) > 0 {
		describeCert(state.TLS.PeerCertificates[0])
	}
	if b, err := quicx.Binding(state.TLS); err == nil {
		fmt.Printf("привязка к сессии: получена, %d байт\n", len(b))
	} else {
		fmt.Printf("привязка к сессии: %v\n", err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	cc := tr.NewClientConn(qc)

	root, err := request(ctx, cc, host, http.MethodGet, "/")
	if err != nil {
		return err
	}
	fmt.Printf("\nGET /            → %s, %d байт\n", root.status, len(root.body))
	if strings.Contains(root.body, "Under construction") {
		fmt.Println("                   заглушка на месте")
	}

	control, err := request(ctx, cc, host, http.MethodPost, node.ControlPath)
	if err != nil {
		return err
	}
	other, err := request(ctx, cc, host, http.MethodPost, "/anything-else")
	if err != nil {
		return err
	}
	fmt.Printf("POST %-12s → %s, %d байт\n", node.ControlPath, control.status, len(control.body))
	fmt.Printf("POST %-12s → %s, %d байт\n", "/anything-else", other.status, len(other.body))

	if control.status == other.status && control.body == other.body {
		fmt.Println("\nуправляющий путь неотличим от любого другого — так и должно быть")
		return nil
	}
	return fmt.Errorf("управляющий путь выдаёт себя: %s против %s", control.status, other.status)
}

type reply struct {
	status string
	body   string
}

func request(ctx context.Context, cc *http3.ClientConn, host, method, path string) (reply, error) {
	req, err := http.NewRequestWithContext(ctx, method, "https://"+host+path, nil)
	if err != nil {
		return reply{}, err
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return reply{}, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return reply{}, err
	}
	return reply{status: resp.Status, body: string(body)}, nil
}

func describeCert(c *x509.Certificate) {
	fmt.Printf("сертификат: %s, выдан %s, до %s\n",
		strings.Join(c.DNSNames, ", "), c.Issuer.CommonName, c.NotAfter.Format(time.DateOnly))
}
