// Package hello — приветствие «свой-чужой».
//
// Как это устроено и почему именно так (решение 001):
//
//  1. Сначала обычное TLS-рукопожатие с настоящим сертификатом. Снаружи это ровно то же
//     самое, что у любого другого сайта на HTTP/3, и до этого момента узел ничем себя не
//     выдаёт.
//  2. Затем, внутри установленного соединения, стороны обмениваются подписанными
//     приветствиями. В открытом виде по сети не едет ничего, что отличало бы наш узел.
//  3. Подписывается привязка к TLS-сессии (см. quicx.Binding), а не произвольный вызов.
//     Поэтому перехваченное приветствие невозможно предъявить где-то ещё: в другой сессии
//     будет другая привязка.
//
// Приветствие взаимное. TLS и так подтверждает имя сервера, но это доверие опирается на
// публичную PKI: ошибочно выданный кому-то сертификат на наш домен ломает его целиком.
// Подпись узла своим ключом такой зависимости не имеет, и клиент проверяет обе.
package hello

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// verify проверяет подпись, не доверяя длинам: и ключ, и подпись приходят от стороны,
// которая себя ещё ничем не подтвердила.
func verify(pub oplog.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// Version — версия приветствия. Правило совместимости из решения 002: N и N−1 обязаны
// работать вместе, иначе волновое обновление сети невозможно.
const Version uint16 = 1

// Role — кем представляется сторона.
type Role uint8

const (
	// RoleNode — узел сети.
	RoleNode Role = 1
	// RoleClient — клиент.
	RoleClient Role = 2
	// RoleAdmin — админское приложение. Отдельная роль нужна затем, что права проверяются
	// по журналу иначе: у админа ключ из списка администраторов, а не из списка клиентов.
	RoleAdmin Role = 3
)

func (r Role) String() string {
	switch r {
	case RoleNode:
		return "node"
	case RoleClient:
		return "client"
	case RoleAdmin:
		return "admin"
	default:
		return fmt.Sprintf("role(%d)", uint8(r))
	}
}

func (r Role) valid() bool { return r >= RoleNode && r <= RoleAdmin }

const (
	// maxIDLen ограничивает длину идентификатора: он приходит от непроверенной ещё стороны,
	// и читать по её слову сколько угодно байт нельзя.
	maxIDLen = 64

	signContext = "qdiver-hello-v1\x00"
)

var (
	ErrBadRole      = errors.New("hello: неизвестная роль")
	ErrBadVersion   = errors.New("hello: несовместимая версия приветствия")
	ErrIDTooLong    = errors.New("hello: идентификатор длиннее допустимого")
	ErrBadSignature = errors.New("hello: подпись не сходится")
	ErrTruncated    = errors.New("hello: приветствие обрывается")
	ErrClockSkew    = errors.New("hello: время собеседника разошлось с нашим")
)

// MaxClockSkew — насколько часы сторон могут разойтись.
//
// Само по себе время ни от чего не защищает: от ретрансляции спасает привязка к сессии.
// Проверка нужна для другого — рассинхронизированные часы ломают разрешение конфликтов в
// журнале, и лучше сказать об этом при первом же соединении, чем разбираться потом с
// правками, приезжающими из будущего.
const MaxClockSkew = 5 * time.Minute

// Hello — приветствие одной стороны.
type Hello struct {
	Version uint16
	Role    Role
	ID      string
	Time    time.Time
	Sig     []byte
}

// signedBytes собирает то, что покрывается подписью: контекст, поля приветствия и привязку
// к сессии. Привязка в поток не пишется — обе стороны выводят её сами.
func (h *Hello) signedBytes(binding []byte) []byte {
	buf := make([]byte, 0, len(signContext)+2+1+2+len(h.ID)+8+len(binding))
	buf = append(buf, signContext...)
	buf = binary.BigEndian.AppendUint16(buf, h.Version)
	buf = append(buf, byte(h.Role))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(h.ID)))
	buf = append(buf, h.ID...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(h.Time.UnixMilli()))
	buf = append(buf, binding...)
	return buf
}

// Sign подписывает приветствие для конкретной сессии.
func (h *Hello) Sign(signer oplog.Signer, binding []byte) error {
	if !h.Role.valid() {
		return fmt.Errorf("%w: %d", ErrBadRole, uint8(h.Role))
	}
	if len(h.ID) > maxIDLen {
		return ErrIDTooLong
	}
	if len(binding) == 0 {
		return errors.New("hello: пустая привязка к сессии")
	}
	h.Time = time.UnixMilli(h.Time.UnixMilli()).UTC()
	sig, err := signer.Sign(h.signedBytes(binding))
	if err != nil {
		return fmt.Errorf("hello: подпись приветствия: %w", err)
	}
	h.Sig = sig
	return nil
}

// Verify проверяет приветствие публичным ключом собеседника и привязкой своей стороны.
func (h *Hello) Verify(pub oplog.PublicKey, binding []byte, now time.Time) error {
	if h.Version != Version {
		return fmt.Errorf("%w: %d, у нас %d", ErrBadVersion, h.Version, Version)
	}
	if !h.Role.valid() {
		return fmt.Errorf("%w: %d", ErrBadRole, uint8(h.Role))
	}
	skew := now.Sub(h.Time)
	if skew < 0 {
		skew = -skew
	}
	if skew > MaxClockSkew {
		return fmt.Errorf("%w: на %s", ErrClockSkew, skew.Round(time.Second))
	}
	if !verify(pub, h.signedBytes(binding), h.Sig) {
		return ErrBadSignature
	}
	return nil
}

// Encode пишет приветствие в поток.
func (h *Hello) Encode(w io.Writer) error {
	if len(h.ID) > maxIDLen {
		return ErrIDTooLong
	}
	buf := make([]byte, 0, 2+1+2+len(h.ID)+8+2+len(h.Sig))
	buf = binary.BigEndian.AppendUint16(buf, h.Version)
	buf = append(buf, byte(h.Role))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(h.ID)))
	buf = append(buf, h.ID...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(h.Time.UnixMilli()))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(h.Sig)))
	buf = append(buf, h.Sig...)
	_, err := w.Write(buf)
	return err
}

// Decode читает приветствие из потока.
//
// Всё, что приходит сюда, прислала ещё не опознанная сторона, поэтому каждая длина
// проверяется до того, как под неё выделяется память.
func Decode(r io.Reader) (*Hello, error) {
	head := make([]byte, 2+1+2)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, wrapRead(err)
	}
	h := &Hello{
		Version: binary.BigEndian.Uint16(head[0:2]),
		Role:    Role(head[2]),
	}
	idLen := binary.BigEndian.Uint16(head[3:5])
	if idLen > maxIDLen {
		return nil, ErrIDTooLong
	}
	if idLen > 0 {
		id := make([]byte, idLen)
		if _, err := io.ReadFull(r, id); err != nil {
			return nil, wrapRead(err)
		}
		h.ID = string(id)
	}

	rest := make([]byte, 8+2)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, wrapRead(err)
	}
	h.Time = time.UnixMilli(int64(binary.BigEndian.Uint64(rest[0:8]))).UTC()

	sigLen := binary.BigEndian.Uint16(rest[8:10])
	if sigLen > 128 {
		return nil, fmt.Errorf("%w: длина подписи %d", ErrBadSignature, sigLen)
	}
	h.Sig = make([]byte, sigLen)
	if _, err := io.ReadFull(r, h.Sig); err != nil {
		return nil, wrapRead(err)
	}
	return h, nil
}

func wrapRead(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return ErrTruncated
	}
	return err
}
