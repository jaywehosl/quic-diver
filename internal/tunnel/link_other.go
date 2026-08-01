//go:build !linux

package tunnel

import (
	"errors"
	"net/netip"
)

// На прочих системах настройка интерфейса своя: на Windows это iphlpapi и NRPT, на Android
// её делает сама VpnService. Здесь честная заглушка, чтобы сборка под них не разъезжалась,
// пока до них не дошли руки.

func (t *Tunnel) Configure([]netip.Addr, bool) error {
	return errors.New("tunnel: настройка интерфейса на этой платформе пока не реализована")
}

func (t *Tunnel) AddRoute(netip.Prefix) error {
	return errors.New("tunnel: настройка маршрутов на этой платформе пока не реализована")
}

func (t *Tunnel) Deconfigure([]netip.Addr) {}
