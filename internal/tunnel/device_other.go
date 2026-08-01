//go:build !linux

package tunnel

import (
	"errors"
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

// openDevice создаёт интерфейс. Готовый дескриптор поддерживает только Linux — там же живёт
// и Android, единственная система, где интерфейс заводит не приложение.
func openDevice(cfg Config) (tun.Device, string, error) {
	if cfg.FD > 0 {
		return nil, "", errors.New("tunnel: интерфейс по дескриптору поддерживается только на Linux")
	}

	dev, err := tun.CreateTUN(cfg.Name, cfg.MTU)
	if err != nil {
		return nil, "", fmt.Errorf("tunnel: создание интерфейса: %w", err)
	}
	name, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, "", fmt.Errorf("tunnel: имя интерфейса: %w", err)
	}
	return dev, name, nil
}
