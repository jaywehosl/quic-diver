package client

import (
	"sync"
	"sync/atomic"
	"time"
)

// Состояние клиента для показа человеку.
//
// Отдельно от журнала намеренно: журнал — это лента событий, по ней нельзя ответить на вопрос
// «что сейчас». А человек, открывший приложение, спрашивает именно это: подключён ли,
// через кого выходит, сколько потратил.
//
// Живёт рядом с клиентом, а не в приложении, потому что источник у всех этих чисел один —
// ядро, и одинаковый на телефоне, на сервере и на Windows. Различается только то, как их
// нарисовать.

// State собирает состояние клиента.
//
// Счётчики байт атомарные и обновляются на каждом потоке; остальное меняется редко и живёт
// под замком. Скорость здесь не считается: она берётся как разница двух опросов, и делать это
// лучше тому, кто рисует, — он знает, как часто спрашивает.
type State struct {
	sent     atomic.Uint64
	received atomic.Uint64

	mu      sync.RWMutex
	stats   Stats
	since   time.Time
	network Network
}

// Network — то, что клиент знает о сети: правила, узлы, параметры.
//
// Отдельно от Stats намеренно. Stats спрашивают раз в секунду, и класть в него полтора десятка
// узлов с ключами и списками адресов означало бы гонять их туда-сюда шестьдесят раз в минуту
// ради чисел, которые меняются раз в сутки. Это спрашивают, когда человек открыл настройки.
type Network struct {
	Name  string     `json:"name"`
	Rules []RuleView `json:"rules"`
	// Nodes — только входные узлы. Выходные клиенту не показываются: он их не выбирает и
	// повлиять на выбор не может, а список выдал бы устройство сети каждому, кто её купил.
	Nodes []NodeView `json:"nodes"`
	// HasEgress — есть ли в сети выходные узлы. Ровно та метка, что и в бандле.
	HasEgress bool         `json:"has_egress"`
	Limit     SettingsView `json:"settings"`
}

// RuleView — правило маршрутизации в том виде, в каком его показывают человеку.
//
// Только чтение: правила задаёт администратор записью в журнал, и клиент их не правит. Своих
// правил у клиента нет вовсе — иначе они разъезжались бы с сетью.
type RuleView struct {
	Match   []string `json:"match"`
	Action  string   `json:"action"`
	Comment string   `json:"comment,omitempty"`
	// Dead — правило, которому нужны базы geosite/geoip, а их нет.
	Dead bool `json:"dead,omitempty"`
}

// NodeView — входной узел сети.
type NodeView struct {
	ID        string   `json:"id"`
	Domain    string   `json:"domain"`
	Endpoints []string `json:"endpoints"`
}

// SettingsView — параметры сети, которые клиента касаются.
//
// Потолки BRUTAL: сеть предлагает, человек вправе перебить свой — свой канал он знает лучше
// администратора, сидящего в другой стране (решение 006).
type SettingsView struct {
	BrutalUpMbps   int `json:"brutal_up_mbps"`
	BrutalDownMbps int `json:"brutal_down_mbps"`
}

// Stats — снимок состояния.
type Stats struct {
	// Connected — есть ли связь с сетью прямо сейчас.
	Connected bool `json:"connected"`
	// Node — узел, с которым связь. Пустой, когда связи нет.
	Node string `json:"node"`
	// ViaEgress — вышел ли последний поток через выходной узел.
	//
	// Признак, а не имя: какой именно выход достался потоку, клиент не знает и знать не
	// должен — выбирает его гонка на входном узле (см. node.ExitVia).
	ViaEgress bool `json:"via_egress"`
	// Network — имя сети из бандла.
	Network string `json:"network"`
	// SinceUnix — когда связь установилась, в секундах эпохи. Ноль означает, что связи нет.
	SinceUnix int64 `json:"since_unix"`

	// Sent и Received — сколько байт прошло через этот клиент с запуска.
	//
	// Свой счёт, а не сетевой: сетевой приходит от узла раз в полминуты и показывает расход
	// за расчётный период, а человеку нужно ещё и «сколько накачал прямо сейчас».
	Sent     uint64 `json:"sent"`
	Received uint64 `json:"received"`

	// Расход по сети — то, что считает сама сеть, и то, чем она меряет лимиты.
	UsageSent     uint64 `json:"usage_sent"`
	UsageReceived uint64 `json:"usage_received"`
	LimitBytes    int64  `json:"limit_bytes"`
	Period        string `json:"period"`
	Devices       int    `json:"devices"`
	DeviceLimit   int    `json:"device_limit"`

	// Rules и Nodes — сколько правил и узлов знает сеть.
	Rules int `json:"rules"`
	Nodes int `json:"nodes"`
	// ViaExit — идёт ли трафик через выходные узлы по умолчанию.
	ViaExit bool `json:"via_exit"`
}

// NewState заводит состояние.
func NewState() *State { return &State{} }

// Stats отдаёт снимок.
func (s *State) Stats() Stats {
	if s == nil {
		return Stats{}
	}

	s.mu.RLock()
	out := s.stats
	if !s.since.IsZero() {
		out.SinceUnix = s.since.Unix()
	}
	s.mu.RUnlock()

	out.Sent = s.sent.Load()
	out.Received = s.received.Load()
	return out
}

// addSent и addReceived прибавляют байты по мере их прохождения.
//
// По мере, а не по завершении потока: замер скорости держит соединение открытым всё время
// работы, и счёт «в конце» показывал бы ноль ровно тогда, когда человек смотрит на экран.
func (s *State) addSent(n uint64) {
	if s != nil {
		s.sent.Add(n)
	}
}

func (s *State) addReceived(n uint64) {
	if s != nil {
		s.received.Add(n)
	}
}

// Connected отмечает связь с узлом.
func (s *State) Connected(node string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.stats.Connected = true
	s.stats.Node = node
	s.since = time.Now()
	s.mu.Unlock()
}

// Disconnected отмечает потерю связи.
//
// Узел не забывается: человеку полезнее видеть «был qdiver1, связи нет», чем пустое место.
func (s *State) Disconnected() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.stats.Connected = false
	s.since = time.Time{}
	s.mu.Unlock()
}

// Exited отмечает, через выход ли пошёл поток.
func (s *State) Exited(viaEgress bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.stats.ViaEgress = viaEgress
	s.mu.Unlock()
}

// SetNetwork называет сеть и умолчание маршрутизации.
func (s *State) SetNetwork(name string, viaExit bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.stats.Network = name
	s.stats.ViaExit = viaExit
	s.mu.Unlock()
}

// Network отдаёт то, что клиент знает о сети.
func (s *State) Network() Network {
	if s == nil {
		return Network{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := s.network
	out.Name = s.stats.Network
	return out
}

// FromSnapshot принимает то, что рассказала сеть.
func (s *State) FromSnapshot(net Network, usage *snapshotUsage) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.network = net
	s.stats.Rules = len(net.Rules)
	s.stats.Nodes = len(net.Nodes)
	if usage == nil {
		return
	}
	s.stats.UsageSent = usage.Sent
	s.stats.UsageReceived = usage.Received
	s.stats.LimitBytes = usage.LimitBytes
	s.stats.Period = usage.Period
	s.stats.Devices = usage.Devices
	s.stats.DeviceLimit = usage.DeviceLimit
}

// snapshotUsage — то же, что control.Usage, но без завязки на пакет control.
type snapshotUsage struct {
	Sent        uint64
	Received    uint64
	LimitBytes  int64
	Period      string
	Devices     int
	DeviceLimit int
}
