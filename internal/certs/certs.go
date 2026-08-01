// Package certs добывает и продлевает настоящий сертификат домена.
//
// Никаких самоподписанных: узел обязан выглядеть как обычный сайт, а обычный сайт с
// самоподписанным сертификатом в 2026 году — сам по себе примета.
//
// Продление идёт без перезапуска: сертификат отдаётся через GetCertificate, и обновлённый
// подхватывается на следующем же рукопожатии (решение 002).
package certs

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"github.com/jaywehosl/quic-diver/internal/quicx"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Manager выдаёт сертификаты одного домена.
type Manager struct {
	domain string
	m      *autocert.Manager
}

// Options — что нужно менеджеру.
type Options struct {
	// Domain — единственное имя, которое узел обслуживает.
	Domain string
	// CacheDir — где хранить выданное. Каталог должен быть закрыт от чужих глаз.
	CacheDir string
	// Email — контакт для удостоверяющего центра, необязателен.
	Email string
	// Directory — каталог ACME. Пустой означает боевой Let's Encrypt.
	Directory string
}

// New собирает менеджер.
func New(opt Options) (*Manager, error) {
	if opt.Domain == "" {
		return nil, errors.New("certs: не задан домен")
	}
	if opt.CacheDir == "" {
		return nil, errors.New("certs: не задан каталог для сертификатов")
	}

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(opt.CacheDir),
		HostPolicy: autocert.HostWhitelist(opt.Domain),
		Email:      opt.Email,
	}
	if opt.Directory != "" {
		m.Client = &acme.Client{DirectoryURL: opt.Directory}
	}
	return &Manager{domain: opt.Domain, m: m}, nil
}

// TLSConfigQUIC — настройки для QUIC.
//
// Здесь только h3. Метод проверки владения доменом acme-tls/1 работает поверх TCP и в этот
// список попасть не должен: лишнее значение в ALPN отличало бы наш узел от других сайтов
// на HTTP/3.
func (m *Manager) TLSConfigQUIC() *tls.Config {
	return &tls.Config{
		GetCertificate: m.m.GetCertificate,
		NextProtos:     []string{quicx.ALPN},
		MinVersion:     tls.VersionTLS13,
	}
}

// TLSConfigTCP — настройки для обычного HTTPS, на котором живёт заглушка.
//
// Порядок в NextProtos обычный для сайта: h2, затем http/1.1. Значение acme-tls/1 нужно
// для проверки владения доменом по TLS-ALPN и в переговорах не участвует.
func (m *Manager) TLSConfigTCP() *tls.Config {
	return &tls.Config{
		GetCertificate: m.m.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
		MinVersion:     tls.VersionTLS12,
	}
}

// HTTPHandler обслуживает проверку владения доменом по HTTP и всё прочее отдаёт fallback.
//
// Обычный сайт на :80 отвечает перенаправлением на https, поэтому и мы отвечаем так же.
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return m.m.HTTPHandler(fallback)
}

// Warm заранее получает сертификат, чтобы первое же соединение не ждало обращения к
// удостоверяющему центру.
func (m *Manager) Warm() error {
	_, err := m.m.GetCertificate(&tls.ClientHelloInfo{
		ServerName:        m.domain,
		SupportedProtos:   []string{quicx.ALPN},
		SupportedVersions: []uint16{tls.VersionTLS13},
	})
	if err != nil {
		return fmt.Errorf("certs: получение сертификата для %s: %w", m.domain, err)
	}
	return nil
}
