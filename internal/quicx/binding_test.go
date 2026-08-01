package quicx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// На привязке к TLS-сессии держится вся проверка «свой-чужой»: узел подписывает не просто
// вызов, а секрет, выведенный из конкретного рукопожатия. Ретрансляция такого приветствия в
// другое соединение бесполезна — там будет другой секрет.
//
// Тест доказывает, что механизм действительно работает поверх quic-go: обе стороны получают
// одинаковое значение, разные сессии дают разные значения, и разная метка тоже.
func TestExporterBindsToSession(t *testing.T) {
	tlsConf, pool := testTLS(t)

	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, ClientConfig(0))
	if err != nil {
		t.Fatalf("слушатель: %v", err)
	}
	defer ln.Close()

	type result struct {
		ekm []byte
		err error
	}
	serverSide := make(chan result, 2)
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			ekm, err := Binding(conn.ConnectionState().TLS)
			serverSide <- result{ekm, err}
		}
	}()

	dial := func() []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{
			RootCAs:    pool,
			ServerName: "qdiver.test",
			NextProtos: []string{ALPN},
		}, ClientConfig(0))
		if err != nil {
			t.Fatalf("соединение: %v", err)
		}
		t.Cleanup(func() { conn.CloseWithError(0, "") })
		ekm, err := Binding(conn.ConnectionState().TLS)
		if err != nil {
			t.Fatalf("привязка на клиенте: %v", err)
		}
		return ekm
	}

	clientFirst := dial()
	first := <-serverSide
	if first.err != nil {
		t.Fatalf("привязка на сервере: %v", first.err)
	}
	if string(clientFirst) != string(first.ekm) {
		t.Fatal("стороны получили разную привязку — подпись не сойдётся")
	}
	if len(clientFirst) != bindingLen {
		t.Fatalf("длина привязки %d, ждали %d", len(clientFirst), bindingLen)
	}

	clientSecond := dial()
	second := <-serverSide
	if second.err != nil {
		t.Fatalf("привязка на сервере: %v", second.err)
	}
	if string(clientSecond) == string(clientFirst) {
		t.Fatal("две сессии дали одну привязку — приветствие можно ретранслировать")
	}
}

func testTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "qdiver.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"qdiver.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("сертификат: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("разбор сертификата: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		NextProtos:   []string{ALPN},
	}, pool
}
