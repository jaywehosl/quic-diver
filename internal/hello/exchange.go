package hello

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Identity — кем представляемся мы сами.
type Identity struct {
	Role   Role
	ID     string
	Signer oplog.Signer
}

// Peer — кем оказался собеседник после успешного приветствия.
type Peer struct {
	Role Role
	ID   string
}

// Directory отвечает на единственный вопрос: чей это ключ.
//
// За ним стоит состояние, собранное из журнала. Отдельный интерфейс нужен затем, чтобы
// приветствие проверялось в тестах без базы и без сети.
type Directory interface {
	// PublicKey возвращает ключ, которым должна проверяться подпись стороны с таким
	// идентификатором и такой ролью. Второе значение — известна ли она вообще.
	PublicKey(role Role, id string) (oplog.PublicKey, bool)
}

// ErrUnknownPeer означает, что такой стороны в журнале нет.
//
// Ошибка намеренно одна на все случаи «нам нечем тебя проверить»: узел не должен по разным
// ответам подсказывать, существует ли такой идентификатор.
var ErrUnknownPeer = errors.New("hello: собеседник неизвестен")

// Recognize выслушивает приветствие и проверяет его, ничего не отвечая.
//
// Отделено от ответа не для красоты. Собеседник, получив наш ответ, немедленно начинает
// пользоваться соединением — открывает потоки, поднимает каналы. Всё, что должно знать об
// опознанном (таблица сессий, учёт), обязано быть готово ДО ответа, иначе первые же его
// запросы застанут узел врасплох и получат отказ. Именно это и случилось на живой сети:
// канал гонки успевал открыться раньше, чем узел отмечал сессию, и получал страницу
// заглушки.
func Recognize(r io.Reader, binding []byte, dir Directory, now time.Time) (*Peer, error) {
	incoming, err := Decode(r)
	if err != nil {
		return nil, err
	}

	pub, ok := dir.PublicKey(incoming.Role, incoming.ID)
	if !ok {
		return nil, fmt.Errorf("%w: %s %q", ErrUnknownPeer, incoming.Role, incoming.ID)
	}
	if err := incoming.Verify(pub, binding, now); err != nil {
		return nil, err
	}
	return &Peer{Role: incoming.Role, ID: incoming.ID}, nil
}

// Respond отвечает своим приветствием.
func Respond(w io.Writer, binding []byte, self Identity, now time.Time) error {
	reply := &Hello{Version: Version, Role: self.Role, ID: self.ID, Time: now}
	if err := reply.Sign(self.Signer, binding); err != nil {
		return err
	}
	if err := reply.Encode(w); err != nil {
		return fmt.Errorf("hello: отправка ответа: %w", err)
	}
	return nil
}

// Accept принимает приветствие и отвечает своим.
//
// Порядок именно такой: сначала выслушиваем, потом отвечаем. Узел, который представляется
// первым, отвечал бы всем подряд, включая случайного сканера, — и тем самым отличал бы себя
// от обычного сайта.
//
// Когда между проверкой и ответом нужно что-то успеть, пользуйся Recognize и Respond
// по отдельности.
func Accept(rw io.ReadWriter, binding []byte, self Identity, dir Directory, now time.Time) (*Peer, error) {
	peer, err := Recognize(rw, binding, dir, now)
	if err != nil {
		return nil, err
	}
	if err := Respond(rw, binding, self, now); err != nil {
		return nil, err
	}
	return peer, nil
}

// Send представляется первым.
//
// Отправка и приём разнесены не для красоты: поверх HTTP/3 между ними обязан встать разбор
// заголовков ответа, и склеенная функция там просто не работает.
func Send(w io.Writer, binding []byte, self Identity, now time.Time) error {
	greeting := &Hello{Version: Version, Role: self.Role, ID: self.ID, Time: now}
	if err := greeting.Sign(self.Signer, binding); err != nil {
		return err
	}
	if err := greeting.Encode(w); err != nil {
		return fmt.Errorf("hello: отправка приветствия: %w", err)
	}
	return nil
}

// Receive принимает ответное приветствие и проверяет его.
//
// expect — публичный ключ, который мы ждём от той стороны: клиент знает его из бандла, узел —
// из журнала. Проверка не лишняя рядом с TLS: TLS подтверждает имя через публичную PKI, и
// ошибочно выданный на наш домен сертификат ломает её целиком, а этот ключ — нет.
func Receive(r io.Reader, binding []byte, expect oplog.PublicKey, now time.Time) (*Peer, error) {
	if len(expect) == 0 {
		return nil, errors.New("hello: не задан ожидаемый ключ собеседника")
	}
	reply, err := Decode(r)
	if err != nil {
		return nil, err
	}
	if err := reply.Verify(expect, binding, now); err != nil {
		return nil, err
	}
	return &Peer{Role: reply.Role, ID: reply.ID}, nil
}

// ReceiveUnchecked принимает ответное приветствие, НЕ проверяя подпись собеседника.
//
// Единственный законный случай — первое знакомство узла с сетью: журнала ещё нет, ключей
// взять неоткуда, и проверять нечем. Защита в этот момент лежит не здесь: всё, что узел
// возьмёт у собеседника, подписано, а отпечаток сети занесён в его конфиг руками, так что
// подсунуть чужую сеть нельзя, кем бы собеседник ни оказался.
//
// Во всех прочих случаях это дыра: сторона не подтверждена ничем, кроме TLS, а TLS ломается
// одним ошибочно выданным сертификатом. Отдельное имя у функции затем и нужно, чтобы такой
// вызов было видно при чтении кода.
func ReceiveUnchecked(r io.Reader, now time.Time) (*Peer, error) {
	reply, err := Decode(r)
	if err != nil {
		return nil, err
	}
	if reply.Version != Version {
		return nil, fmt.Errorf("%w: %d, у нас %d", ErrBadVersion, reply.Version, Version)
	}
	if !reply.Role.valid() {
		return nil, fmt.Errorf("%w: %d", ErrBadRole, uint8(reply.Role))
	}
	return &Peer{Role: reply.Role, ID: reply.ID}, nil
}

// Initiate представляется и сразу же ждёт ответа. Годится там, где между записью и чтением
// ничего не вклинивается: поток без обрамления, тесты.
func Initiate(rw io.ReadWriter, binding []byte, self Identity, expect oplog.PublicKey, now time.Time) (*Peer, error) {
	if err := Send(rw, binding, self, now); err != nil {
		return nil, err
	}
	return Receive(rw, binding, expect, now)
}

// StateDirectory берёт ключи из состояния, собранного журналом.
type StateDirectory struct{ State *oplog.State }

// PublicKey ищет ключ по роли и идентификатору.
func (d StateDirectory) PublicKey(role Role, id string) (oplog.PublicKey, bool) {
	switch role {
	case RoleNode:
		n, ok := d.State.Node(id)
		if !ok {
			return nil, false
		}
		return n.PublicKey, true

	case RoleClient:
		c, ok := d.State.Client(id)
		if !ok || c.Suspended {
			// Приостановленный клиент для приветствия всё равно что незнакомый: раз он
			// приостановлен, дальше рукопожатия ему ходу нет, и знать об этом ему незачем.
			return nil, false
		}
		if c.ExpiresAt != nil && time.Now().After(*c.ExpiresAt) {
			return nil, false
		}
		return c.PublicKey, true

	case RoleAdmin:
		key, err := oplog.ParseKeyID(id)
		if err != nil {
			return nil, false
		}
		admin, ok := d.State.AdminKey(key)
		if !ok {
			return nil, false
		}
		return admin.PublicKey, true

	default:
		return nil, false
	}
}
