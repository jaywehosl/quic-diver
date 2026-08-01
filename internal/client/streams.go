package client

import (
	"io"
	"sync"
)

// streams — реестр живых потоков через сеть.
//
// # Зачем
//
// Умолчание маршрутизации меняется на ходу, но уже открытый поток остаётся там, где был:
// перенести установленный TLS-сеанс на другой выходной узел нельзя, он просто оборвётся.
//
// Само по себе это верно, а вот наблюдаемое поведение получалось половинчатым. Браузер
// держит соединения открытыми минутами и переиспользует их: человек снимает галку, обновляет
// страницу — и видит прежний адрес, потому что нового соединения никто не открывал. Одна
// вкладка при этом показывает одно, другая — другое.
//
// Поэтому переключение закрывает открытые потоки. Обрыв здесь честнее половинчатости:
// приложение переоткроет соединение само и уже по новому маршруту, а человек увидит ровно
// то, что выбрал.
type streams struct {
	mu   sync.Mutex
	next uint64
	live map[uint64]io.Closer
}

func newStreams() *streams { return &streams{live: make(map[uint64]io.Closer)} }

// add берёт поток на учёт и возвращает метку для снятия.
func (s *streams) add(c io.Closer) uint64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.next++
	id := s.next
	s.live[id] = c
	return id
}

// remove снимает поток с учёта: он закончился сам.
func (s *streams) remove(id uint64) {
	if s == nil || id == 0 {
		return
	}
	s.mu.Lock()
	delete(s.live, id)
	s.mu.Unlock()
}

// closeAll закрывает всё, что открыто, и отвечает, скольких это коснулось.
func (s *streams) closeAll() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	live := s.live
	s.live = make(map[uint64]io.Closer)
	s.mu.Unlock()

	for _, c := range live {
		// Ошибку смотреть незачем: поток закрывают, а не читают, и его половина могла
		// закрыться сама секундой раньше.
		_ = c.Close()
	}
	return len(live)
}

// pair закрывает обе половины потока разом.
//
// Закрыть одну мало: копирование идёт в обе стороны, и половина, оставшаяся открытой, держала
// бы горутину до тех пор, пока другая сторона не догадается уйти сама.
type pair struct {
	local  io.Closer
	remote io.Closer
}

func (p pair) Close() error {
	_ = p.local.Close()
	return p.remote.Close()
}
