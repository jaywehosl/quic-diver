//go:build linux

package tunnel

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

// openDevice берёт интерфейс: готовый по дескриптору или созданный нами.
//
// Готовый — это Android: там устройство заводит система по запросу приложения, а нам достаётся
// открытый дескриптор. Прав создавать своё у приложения нет, и не нужно: маршруты и адреса
// система расставит сама, по тому, что приложение попросило у VpnService.
func openDevice(cfg Config) (tun.Device, string, error) {
	if cfg.FD > 0 {
		dev, name, err := tun.CreateUnmonitoredTUNFromFD(cfg.FD)
		if err != nil {
			return nil, "", fmt.Errorf("tunnel: интерфейс по дескриптору %d: %w", cfg.FD, err)
		}
		return dev, name, nil
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
