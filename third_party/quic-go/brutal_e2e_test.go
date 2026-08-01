package quic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Правка форка QUIC Diver: проверка, что потолок BRUTAL действительно ограничивает отправку
// на живом соединении, а не только в модульных тестах алгоритма (решение 006).

func brutalTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "brutal.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"brutal.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
			NextProtos:   []string{"brutal-test"},
		}, &tls.Config{
			RootCAs:    pool,
			ServerName: "brutal.test",
			NextProtos: []string{"brutal-test"},
		}
}

// measureBrutal шлёт заданный объём с указанным потолком и возвращает достигнутую скорость
// в мегабитах в секунду.
func measureBrutal(t *testing.T, sendMbps int, payload int) float64 {
	t.Helper()
	serverTLS, clientTLS := brutalTLS(t)

	ln, err := ListenAddr("127.0.0.1:0", serverTLS, &Config{})
	require.NoError(t, err)
	defer ln.Close()

	received := make(chan int64, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			received <- 0
			return
		}
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			received <- 0
			return
		}
		n, _ := io.Copy(io.Discard, str)
		received <- n
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := DialAddr(ctx, ln.Addr().String(), clientTLS, &Config{BrutalSendMbps: sendMbps})
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)

	data := make([]byte, payload)
	start := time.Now()
	_, err = str.Write(data)
	require.NoError(t, err)
	require.NoError(t, str.Close())

	select {
	case n := <-received:
		require.EqualValues(t, payload, n)
	case <-time.After(60 * time.Second):
		t.Fatal("данные не доехали")
	}
	elapsed := time.Since(start)

	return float64(payload) * 8 / 1e6 / elapsed.Seconds()
}

// Потолок обязан ограничивать: без него петля выдаёт сотни мегабит, с ним — заданное число.
func TestBrutalLimitsThroughput(t *testing.T) {
	const (
		limitMbps = 20
		payload   = 4 << 20 // 4 МиБ: при 20 Мбит/с это около полутора секунд
	)

	limited := measureBrutal(t, limitMbps, payload)
	t.Logf("с потолком %d Мбит/с получилось %.1f Мбит/с", limitMbps, limited)

	// Запас вдвое: пейсер отдаёт с небольшим превышением, и на петле разгон почти мгновенный.
	require.Less(t, limited, float64(limitMbps)*2,
		"потолок не ограничивает: получено %.1f Мбит/с при заданных %d", limited, limitMbps)

	free := measureBrutal(t, 0, payload)
	t.Logf("без потолка получилось %.1f Мбит/с", free)
	require.Greater(t, free, limited, "без потолка должно быть быстрее")
}
