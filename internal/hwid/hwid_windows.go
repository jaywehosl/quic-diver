//go:build windows

package hwid

import "golang.org/x/sys/windows/registry"

// machineID берёт MachineGuid — значение, которое Windows заводит при установке и хранит
// всё время жизни системы.
func machineID() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer key.Close()

	guid, _, err := key.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return guid
}
