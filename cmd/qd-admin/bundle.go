package main

import (
	"crypto/ed25519"
	"fmt"

	"github.com/jaywehosl/quic-diver/internal/bundle"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Выпуск бандла.
//
// Приватный ключ клиента рождается у админа и нигде не сохраняется — в журнале только
// публичная часть. Поэтому бандл печатается там же, где ключ рождается, и второй раз выдать
// его нельзя. Потерянный бандл лечится перевыпуском (решение 004 §1.4).

// makeBundle собирает бандл по текущему состоянию сети.
func makeBundle(state *oplog.State, clientID string, key ed25519.PrivateKey) (*bundle.Bundle, error) {
	if state.Genesis().IsZero() {
		return nil, fmt.Errorf("сеть ещё не создана")
	}

	b := &bundle.Bundle{
		Version:   bundle.Version,
		Network:   state.Network(),
		Genesis:   state.Genesis(),
		ClientID:  clientID,
		ClientKey: key,
		Settings:  state.Settings(),
	}

	for _, n := range state.NodesWithRole(oplog.RoleIngress) {
		b.Ingress = append(b.Ingress, bundle.Node{
			ID:        n.ID,
			Domain:    n.Domain,
			Endpoints: n.Endpoints,
			PublicKey: n.PublicKey,
		})
	}
	// Признак нужен ради чекбокса: без выходных узлов «через выходные» нечего и предлагать.
	b.HasEgress = len(state.NodesWithRole(oplog.RoleEgress)) > 0

	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// printBundle печатает ссылку и говорит человеку, как с ней обращаться.
func printBundle(b *bundle.Bundle, password string) error {
	uri, err := bundle.Encode(b, password)
	if err != nil {
		return err
	}

	fmt.Printf("\nбандл для клиента %s (сеть %s, узлов на входе %d):\n\n  %s\n\n",
		b.ClientID, b.Network, len(b.Ingress), uri)

	if password == "" {
		fmt.Println("Ссылка не зашифрована и содержит приватный ключ клиента —")
		fmt.Println("обращайся с ней как с ключом. Передавать открытым каналом нельзя.")
		fmt.Println("Пароль задаётся флагом -password: тогда перехваченная ссылка бесполезна.")
	} else {
		fmt.Println("Ссылка зашифрована паролем. Пароль передавай отдельно от ссылки —")
		fmt.Println("иначе шифрование не защищает ни от чего.")
	}
	fmt.Println("\nВторой раз бандл не выдать: приватный ключ нигде не сохранён.")
	fmt.Println("Потерян — перевыпусти: qd-admin client reissue " + b.ClientID)
	return nil
}
