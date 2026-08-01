//go:build !linux && !windows

package hwid

// machineID на прочих системах ищет то, что есть.
//
// На macOS устойчивое значение достаётся из IOKit, на Android — из Settings.Secure; и то и
// другое требует своих вызовов и появится вместе с клиентами под эти системы. До тех пор
// устройство остаётся безымянным, и лимит устройств его не считает — это честнее, чем
// придумать идентификатор, который меняется при каждом запуске.
func machineID() string {
	return readFirst("/etc/machine-id", "/var/lib/dbus/machine-id")
}
