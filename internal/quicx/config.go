// Package quicx держит профили QUIC-соединений проекта.
//
// Профилей два, и они разные не по вкусу, а по природе участков:
//
//   - клиент↔узел живёт за NAT и на мобильной сети, где адрес меняется, а роутер моргает.
//     Ему нужна терпимость: длинный idle и частый keep-alive, чтобы не терять связь на ровном месте.
//   - узел↔узел — это статика с обеих сторон. Здесь терпимость вредна: мёртвая связь означает,
//     что транзитные потоки уходят в пустоту, и чем позже мы это заметим, тем дольше человек
//     смотрит на белый экран. Поэтому пороги втрое жёстче.
//
// Числа ниже — стартовые значения. По решению 001 всё, что можно менять на лету, живёт в
// журнале; сюда они попадут как значения по умолчанию, когда появится подписка на снапшот.
package quicx

import (
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ALPN сети — обычный h3. Свой ALPN был бы виден в открытом ClientHello и отличал бы наши
// узлы от любого другого сайта на HTTP/3, то есть работал бы ровно против требования
// «не отличаться от нормального QUIC».
const ALPN = http3.NextProtoH3

const (
	// Клиент за NAT: запись в таблице трансляции живёт обычно 30–60 с, поэтому стучимся чаще.
	clientIdleTimeout = 30 * time.Second
	clientKeepAlive   = 10 * time.Second

	// Между узлами адреса статические, терять время на подтверждение смерти незачем.
	meshIdleTimeout = 15 * time.Second
	meshKeepAlive   = 5 * time.Second

	// Рукопожатие: гонка и так отбрасывает опоздавших, но узел не должен держать
	// недоделанные соединения дольше нужного.
	handshakeIdleTimeout = 5 * time.Second

	// Клиент терминирует потоки локально, значит каждый TCP-флоу пользователя — отдельный
	// стрим к узлу. Дефолтные 100 у quic-go кончаются на первой же тяжёлой странице.
	clientMaxIncomingStreams = 2048
	meshMaxIncomingStreams   = 8192
)

// ClientConfig — профиль соединения клиент↔узел, одинаковый для обеих сторон.
//
// sendMbps — потолок BRUTAL для **своей** отправки (решение 006). Ноль означает обычный
// Cubic. У клиента и узла числа разные: клиент отдаёт вверх, узел — вниз, и у домашнего
// канала эти половины несимметричны.
func ClientConfig(sendMbps int) *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:       clientIdleTimeout,
		KeepAlivePeriod:      clientKeepAlive,
		HandshakeIdleTimeout: handshakeIdleTimeout,
		MaxIncomingStreams:   clientMaxIncomingStreams,
		// Датаграммы нужны для проксирования UDP-потоков пользователя (RFC 9298).
		EnableDatagrams: true,
		BrutalSendMbps:  sendMbps,
	}
}

// MeshConfig — профиль соединения узел↔узел.
func MeshConfig(sendMbps int) *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:       meshIdleTimeout,
		KeepAlivePeriod:      meshKeepAlive,
		HandshakeIdleTimeout: handshakeIdleTimeout,
		MaxIncomingStreams:   meshMaxIncomingStreams,
		// Датаграммы несут и пользовательский UDP, и гонку OFFER/TAKE из решения 001.
		EnableDatagrams: true,
		BrutalSendMbps:  sendMbps,
	}
}
