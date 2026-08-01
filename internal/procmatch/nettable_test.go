package procmatch

import (
	"net/netip"
	"strings"
	"testing"
)

// Настоящий кусок /proc/net/tcp: заголовок и три соединения.
const tcpTable = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0438 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 21456 1 0000000000000000 100 0 0 10 0
   1: 0100007F:B7A2 0100007F:0438 01 00000000:00000000 00:00000000 00000000  1000        0 38221 1 0000000000000000 20 4 30 10 -1
   2: F5D9A8C0:C1B4 8EFA1AD8:01BB 01 00000000:00000000 02:00000AC5 00000000  1000        0 41007 1 0000000000000000 22 4 26 10 -1
`

// Кусок /proc/net/tcp6: петля и внешнее соединение.
const tcp6Table = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0438 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 21460 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:C000 0000000000000000FFFF00000100007F:0438 01 00000000:00000000 00:00000000 00000000  1000        0 38300 1 0000000000000000 20 4 30 10 -1
`

func TestParseAddressesAndPorts(t *testing.T) {
	entries, err := parseNetTable(strings.NewReader(tcpTable))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("строк разобрано: %d, ждали 3", len(entries))
	}

	// 0100007F:0438 — это 127.0.0.1:1080, порядок байтов узла.
	want := netip.MustParseAddrPort("127.0.0.1:1080")
	if entries[0].local != want {
		t.Fatalf("слушающий сокет разобран как %s, ждали %s", entries[0].local, want)
	}
	if entries[0].inode != 21456 {
		t.Fatalf("инод: %d", entries[0].inode)
	}

	// Клиентское соединение на тот же порт.
	if entries[1].remote != want {
		t.Fatalf("дальний конец: %s", entries[1].remote)
	}
	if entries[1].local != netip.MustParseAddrPort("127.0.0.1:47010") {
		t.Fatalf("ближний конец: %s", entries[1].local)
	}

	// Внешнее соединение: F5D9A8C0 = 192.168.217.245, 8EFA1AD8 = 216.26.250.142:443.
	if entries[2].local.Addr().String() != "192.168.217.245" {
		t.Fatalf("внешний ближний конец: %s", entries[2].local)
	}
	if entries[2].remote.Port() != 443 {
		t.Fatalf("внешний порт: %d", entries[2].remote.Port())
	}
}

// Адреса v6 записаны четырьмя словами, каждое в порядке узла. Переворачивать надо внутри
// слова, а не весь адрес — на этом легко ошибиться, поэтому проверяется отдельно.
func TestParseIPv6AddressWordOrder(t *testing.T) {
	entries, err := parseNetTable(strings.NewReader(tcp6Table))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("строк разобрано: %d", len(entries))
	}

	// ::ffff:127.0.0.1 после Unmap превращается в 127.0.0.1.
	got := entries[1].local.Addr()
	if got.String() != "127.0.0.1" {
		t.Fatalf("v4-in-v6 разобран как %s", got)
	}
}

// Оба конца должны совпасть: на петле полно соединений с одним и тем же портом назначения,
// и по одному концу процесс определился бы неверно — то есть трафик ушёл бы не туда.
func TestBothEndpointsMustMatch(t *testing.T) {
	entries, err := parseNetTable(strings.NewReader(tcpTable))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}

	local := netip.MustParseAddrPort("127.0.0.1:47010")
	remote := netip.MustParseAddrPort("127.0.0.1:1080")

	inode, ok := findInode(entries, local, remote)
	if !ok {
		t.Fatal("соединение не найдено")
	}
	if inode != 38221 {
		t.Fatalf("найден инод %d, ждали 38221", inode)
	}

	// Тот же дальний конец, но другой ближний — это другое соединение.
	if _, ok := findInode(entries, netip.MustParseAddrPort("127.0.0.1:47011"), remote); ok {
		t.Fatal("нашлось соединение с чужим ближним концом")
	}
	// И наоборот.
	if _, ok := findInode(entries, local, netip.MustParseAddrPort("127.0.0.1:1081")); ok {
		t.Fatal("нашлось соединение с чужим дальним концом")
	}
}

// Ядро может показать петлю как ::ffff:127.0.0.1, а клиент прислать 127.0.0.1.
func TestMappedAddressesAreTheSameEndpoint(t *testing.T) {
	entries, err := parseNetTable(strings.NewReader(tcp6Table))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}

	local := netip.MustParseAddrPort("127.0.0.1:49152")
	remote := netip.MustParseAddrPort("127.0.0.1:1080")
	if _, ok := findInode(entries, local, remote); !ok {
		t.Fatal("соединение из таблицы v6 не найдено по адресам v4")
	}
}

func TestGarbageLinesAreSkipped(t *testing.T) {
	table := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: мусор
   1: 0100007F:0438 00000000:0000 0A
   2: 0100007F:B7A2 0100007F:0438 01 00000000:00000000 00:00000000 00000000  1000        0 38221 1 0000000000000000 20 4 30 10 -1
`
	entries, err := parseNetTable(strings.NewReader(table))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("разобрано строк: %d, ждали 1 — остальные негодные", len(entries))
	}
}

func TestEmptyTable(t *testing.T) {
	entries, err := parseNetTable(strings.NewReader("  sl  local_address rem_address\n"))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("в пустой таблице нашлось %d строк", len(entries))
	}
}

// Заглушка обязана честно говорить, что не умеет, а не притворяться, будто процесса нет.
func TestNopSaysUnsupported(t *testing.T) {
	_, err := Nop().Lookup(netip.MustParseAddrPort("127.0.0.1:1"), netip.MustParseAddrPort("127.0.0.1:2"))
	if err != ErrUnsupported {
		t.Fatalf("заглушка вернула %v", err)
	}
}
