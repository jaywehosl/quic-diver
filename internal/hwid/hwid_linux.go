//go:build linux

package hwid

// machineID берёт общесистемный идентификатор машины.
//
// Два пути, потому что systemd кладёт файл в /etc, а на системах без него он живёт в
// /var/lib/dbus. Второй заодно переживает пересоздание /etc/machine-id.
func machineID() string {
	return readFirst("/etc/machine-id", "/var/lib/dbus/machine-id")
}
