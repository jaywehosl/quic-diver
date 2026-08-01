package node

import (
	"encoding/base64"
	"sync"
	"time"

	"github.com/jaywehosl/quic-diver/internal/hello"
)

// sessions помнит, кто прошёл приветствие.
//
// Приветствие происходит один раз, на управляющем потоке, а потоки трафика приходят
// отдельными запросами того же соединения. Подписывать каждый из них значило бы платить
// проверкой подписи за каждый открытый пользователем сайт.
//
// Ключом служит привязка к TLS-сессии: она одинакова для всех запросов внутри одного
// QUIC-соединения и разная у разных соединений (это проверено тестом в quicx). Поэтому
// «тот же, кто здоровался» определяется без обращения к внутренностям quic-go и без
// собственных идентификаторов, которые пришлось бы защищать от подделки.
type sessions struct {
	mu   sync.RWMutex
	live map[string]*session
}

type session struct {
	peer  *hello.Peer
	since time.Time
	// device и addr — чем клиент назвался и откуда пришёл. Нужны, чтобы отметить работающее
	// устройство при первом же прикладном запросе.
	device string
	addr   string
	// active — отмечали ли уже это соединение работающим.
	//
	// Отметка ставится не на приветствие, а на первый прикладной запрос (решение 001 §2):
	// гонка рукопожатий оставляет по соединению на каждом адресе каждого входного узла, и
	// все они здороваются успешно. Считать их работающими значило бы, что клиент сам себе
	// накрутил лимит устройств вчетверо.
	active bool
}

func newSessions() *sessions {
	return &sessions{live: make(map[string]*session)}
}

func key(binding []byte) string {
	return base64.RawStdEncoding.EncodeToString(binding)
}

// add отмечает соединение как опознанное и возвращает функцию, снимающую отметку.
//
// onGone зовётся при закрытии, но только если соединение успело поработать: у проигравших
// гонку отмечать нечего, а звать уход за них — значит убрать сессию победителя.
func (s *sessions) add(binding []byte, peer *hello.Peer, device, addr string, onGone func()) func() {
	k := key(binding)

	s.mu.Lock()
	s.live[k] = &session{peer: peer, since: time.Now(), device: device, addr: addr}
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		sess, ok := s.live[k]
		delete(s.live, k)
		s.mu.Unlock()

		if ok && sess.active && onGone != nil {
			onGone()
		}
	}
}

// lookup ищет, кому принадлежит соединение.
func (s *sessions) lookup(binding []byte) (*hello.Peer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.live[key(binding)]
	if !ok {
		return nil, false
	}
	return sess.peer, true
}

// activate отмечает соединение работающим и говорит, случилось ли это впервые.
//
// Впервые — значит пора сказать сети, что устройство клиента работает здесь. Дальнейшие
// запросы того же соединения ничего не меняют.
func (s *sessions) activate(binding []byte) (device, addr string, first bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.live[key(binding)]
	if !ok || sess.active {
		return "", "", false
	}
	sess.active = true
	return sess.device, sess.addr, true
}

// count возвращает число опознанных соединений — для наблюдаемости.
func (s *sessions) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.live)
}
