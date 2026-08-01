package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jaywehosl/quic-diver/internal/control"
	"github.com/jaywehosl/quic-diver/internal/link"
	"github.com/jaywehosl/quic-diver/internal/node"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Клиент помнит сеть (решение 007 §4).
//
// # Зачем
//
// Ссылка на сеть — слепок на момент выдачи: в ней перечислены входные узлы, какими они были в
// тот день. Добавили узел, сменили адрес, отозвали старый — и слепок устарел, а исправить его
// можно было только новой ссылкой, то есть сменой ключа клиента. Человеку приходилось вставлять
// новую ссылку из-за события, к нему не относящегося вовсе.
//
// ТЗ (ст. 32) требует обратного: клиент сам запрашивает сведения о работающих узлах и
// обновляется. Узел их и так присылает — снапшотом, по уже открытому каналу, на каждое
// изменение журнала. Не хватало только одного: запомнить присланное до следующего запуска.
//
// # Граница доверия
//
// Запомненное **не заменяет** ссылку, а дополняет её. Ключ клиента, пароль и отпечаток сети
// берутся только из ссылки; из памяти приходит лишь список узлов и параметры. Отпечаток
// сверяется при чтении: файл от другой сети отбрасывается целиком, даже если лежит по нужному
// пути.
//
// Это не защита от подмены файла — у того, кто пишет в каталог клиента, и так есть всё
// остальное. Это защита от путаницы: две сети на одном устройстве, смена ссылки, перенос
// каталога.

// rememberFile — имя файла в каталоге состояния.
const rememberFile = "network.json"

// remembered — сведения о сети, пережившие перезапуск.
type remembered struct {
	// Genesis — чья это сеть. Не совпал с бандлом — файл не наш.
	Genesis oplog.Fingerprint `json:"genesis"`
	Network string            `json:"network"`
	// Nodes — входные узлы с ключами: без ключа к узлу не подключиться, приветствие не сойдётся.
	Nodes    []rememberedNode `json:"nodes"`
	Egress   bool             `json:"egress"`
	Settings oplog.Settings   `json:"settings"`
	// SavedUnix — когда записано. Человеку показывается «сведения от такого-то числа».
	SavedUnix int64 `json:"saved_unix"`
}

type rememberedNode struct {
	ID        string          `json:"id"`
	Domain    string          `json:"domain"`
	Endpoints []string        `json:"endpoints"`
	PublicKey oplog.PublicKey `json:"public_key"`
}

func (r remembered) targets() []node.Target {
	out := make([]node.Target, 0, len(r.Nodes))
	for _, n := range r.Nodes {
		out = append(out, node.Target{
			ID:        n.ID,
			Domain:    n.Domain,
			Endpoints: n.Endpoints,
			PublicKey: n.PublicKey,
		})
	}
	return out
}

// rememberOf собирает то, что стоит запомнить, из целей и параметров.
func rememberOf(genesis oplog.Fingerprint, name string, targets []node.Target, egress bool, settings oplog.Settings, now time.Time) remembered {
	r := remembered{
		Genesis:   genesis,
		Network:   name,
		Egress:    egress,
		Settings:  settings,
		SavedUnix: now.Unix(),
	}
	for _, t := range targets {
		r.Nodes = append(r.Nodes, rememberedNode{
			ID:        t.ID,
			Domain:    t.Domain,
			Endpoints: t.Endpoints,
			PublicKey: t.PublicKey,
		})
	}
	return r
}

// loadRemembered читает запомненное, если оно от этой же сети.
//
// Любая беда здесь — не беда: клиент просто пойдёт по узлам из ссылки, как ходил раньше.
// Поэтому возвращается пустое значение, а не ошибка.
func loadRemembered(dir string, genesis oplog.Fingerprint, log *slog.Logger) (remembered, bool) {
	if dir == "" {
		return remembered{}, false
	}
	raw, err := os.ReadFile(filepath.Join(dir, rememberFile))
	if err != nil {
		if !os.IsNotExist(err) {
			log.Debug("запомненная сеть не прочиталась", "err", err)
		}
		return remembered{}, false
	}

	var r remembered
	if err := json.Unmarshal(raw, &r); err != nil {
		log.Warn("запомненная сеть испорчена, беру узлы из ссылки", "err", err)
		return remembered{}, false
	}
	if len(r.Nodes) == 0 {
		return remembered{}, false
	}
	// Отпечаток из ссылки — единственное, чем эти два источника связаны. Пустой означает, что
	// ссылки нет вовсе (клиент запущен флагами, для отладки), и сверять нечем.
	if !genesis.IsZero() && r.Genesis != genesis {
		log.Warn("запомненная сеть от другой сети, не беру",
			"ждали", genesis.String()[:16], "в файле", r.Genesis.String()[:16])
		return remembered{}, false
	}
	return r, true
}

// saveRemembered записывает сведения о сети.
//
// Пишется через временный файл: обрыв посреди записи оставил бы обрезанный JSON, а разбирать
// его пришлось бы при следующем запуске — то есть ровно тогда, когда узлы нужнее всего.
func saveRemembered(dir string, r remembered) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("каталог состояния: %w", err)
	}

	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("сборка запомненной сети: %w", err)
	}

	final := filepath.Join(dir, rememberFile)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("запись запомненной сети: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("замена запомненной сети: %w", err)
	}
	return nil
}

// RememberNetwork записывает сведения о сети, полученные не от узла.
//
// Нужно владельцу и только ему. Обычный клиент узнаёт узлы двумя путями — из ссылки и снапшотом
// по живой связи, — и оба ему доступны. У владельца в момент создания сети нет ни того, ни
// другого: ссылку он выдал себе сам, когда узлов ещё не существовало, а связаться не с кем
// ровно потому, что узлов в ссылке нет.
//
// Круг разрывается здесь: узел, который владелец только что включил в сеть, лежит в его
// собственном журнале — оттуда сведения и берутся, без всякой сети.
func RememberNetwork(dir string, snap control.Snapshot, log *slog.Logger) error {
	if dir == "" {
		return fmt.Errorf("client: не задан каталог состояния")
	}
	if len(snap.Nodes) == 0 {
		return fmt.Errorf("client: в снимке нет ни одного входного узла")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	before, _ := loadRemembered(dir, snap.Genesis, log)
	memory := &networkMemory{dir: dir, genesis: snap.Genesis, known: before}
	memory.apply(snap, log)
	return nil
}

// networkMemory применяет присланное сетью и хранит его до следующего запуска.
//
// Живёт рядом со связью, а не внутри неё: связь про журнал сети не знает ничего, а память —
// про гонку. Здесь они и встречаются.
type networkMemory struct {
	dir     string
	genesis oplog.Fingerprint
	link    *link.Link
	// known — то, что уже записано. Держится затем, чтобы не переписывать файл на каждый
	// снапшот: узел присылает их и по таймеру расхода, дважды в минуту.
	known remembered
}

// apply принимает снапшот: обновляет узлы для гонки и, если состав изменился, пишет на диск.
func (m *networkMemory) apply(snap control.Snapshot, log *slog.Logger) {
	if m == nil || len(snap.Nodes) == 0 {
		return
	}

	targets := make([]node.Target, 0, len(snap.Nodes))
	for _, n := range snap.Nodes {
		targets = append(targets, node.Target{
			ID:        n.ID,
			Domain:    n.Domain,
			Endpoints: n.Endpoints,
			PublicKey: n.PublicKey,
		})
	}

	if sameNodes(m.known.Nodes, targets) && m.known.Egress == snap.Egress {
		return
	}

	if m.link != nil && m.link.SetTargets(targets) {
		log.Info("сеть обновила список входных узлов",
			"было", len(m.known.Nodes), "стало", len(targets))
	}

	m.known = rememberOf(m.genesis, snap.Network, targets, snap.Egress, snap.Settings, time.Now())
	if err := saveRemembered(m.dir, m.known); err != nil {
		// Не беда для этого запуска: узлы уже применены, и клиент работает по ним. Потеряется
		// только память о них — при следующем запуске в ход пойдёт список из ссылки.
		log.Warn("сеть не запомнилась", "err", err)
	}
}

// sameNodes сравнивает списки узлов по существу.
//
// Нужно затем, чтобы не переписывать файл на каждый снапшот: узел присылает его и по таймеру
// расхода, то есть дважды в минуту, а сеть меняется раз в месяц.
func sameNodes(a []rememberedNode, b []node.Target) bool {
	if len(a) != len(b) {
		return false
	}
	// Порядок значим: он приходит из журнала и одинаков у всех узлов сети. Совпадающий по
	// составу, но переставленный список — событие настолько редкое, что лишняя запись файла
	// дешевле сортировки на каждом снапшоте.
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Domain != b[i].Domain {
			return false
		}
		if !bytes.Equal(a[i].PublicKey, b[i].PublicKey) {
			return false
		}
		if len(a[i].Endpoints) != len(b[i].Endpoints) {
			return false
		}
		for j := range a[i].Endpoints {
			if a[i].Endpoints[j] != b[i].Endpoints[j] {
				return false
			}
		}
	}
	return true
}
