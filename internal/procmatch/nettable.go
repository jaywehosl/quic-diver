package procmatch

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Разбор таблиц соединений ядра (/proc/net/tcp и /proc/net/tcp6).
//
// Вынесен отдельно от файловой системы намеренно: формат нехитрый, но с двумя ловушками —
// порядком байтов и представлением адресов v6, — и проверять его надо на подготовленных
// данных, а не на живой машине, где в таблице то одно, то другое.

// entry — строка таблицы.
type entry struct {
	local  netip.AddrPort
	remote netip.AddrPort
	inode  uint64
}

// parseNetTable разбирает таблицу соединений.
//
// Формат такой:
//
//	sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
//	 0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 ...
//
// Адреса записаны шестнадцатерично и в порядке байтов узла — то есть на обычной машине
// задом наперёд. Отсюда и берётся `0100007F` для 127.0.0.1.
func parseNetTable(r io.Reader) ([]entry, error) {
	sc := bufio.NewScanner(r)
	// Строки короткие, но таблица бывает длинной: увеличиваем буфер, чтобы не спотыкаться
	// на неожиданно длинной строке.
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	var out []entry
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			// Заголовок.
			first = false
			continue
		}
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		local, err := parseAddrPort(fields[1])
		if err != nil {
			continue
		}
		remote, err := parseAddrPort(fields[2])
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, entry{local: local, remote: remote, inode: inode})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("procmatch: чтение таблицы соединений: %w", err)
	}
	return out, nil
}

// parseAddrPort разбирает "0100007F:1F90".
func parseAddrPort(s string) (netip.AddrPort, error) {
	hexAddr, hexPort, found := strings.Cut(s, ":")
	if !found {
		return netip.AddrPort{}, fmt.Errorf("procmatch: адрес %q без порта", s)
	}

	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("procmatch: порт %q: %w", hexPort, err)
	}

	raw, err := hex.DecodeString(hexAddr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("procmatch: адрес %q: %w", hexAddr, err)
	}

	var addr netip.Addr
	switch len(raw) {
	case 4:
		// Четыре байта в порядке узла: переворачиваем.
		addr = netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]})
	case 16:
		// Адрес v6 записан четырьмя словами, и каждое — в порядке узла. Переворачивать
		// нужно внутри слова, а не весь адрес целиком: это та самая ловушка, из-за которой
		// разбор и вынесен под тесты.
		var b [16]byte
		for i := 0; i < 4; i++ {
			word := binary.LittleEndian.Uint32(raw[i*4 : i*4+4])
			binary.BigEndian.PutUint32(b[i*4:i*4+4], word)
		}
		addr = netip.AddrFrom16(b)
	default:
		return netip.AddrPort{}, fmt.Errorf("procmatch: адрес длиной %d байт", len(raw))
	}

	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}

// findInode ищет инод сокета по концам соединения.
//
// Сравниваются оба конца: на локальной петле полно соединений с одинаковым портом
// назначения, и по одному концу процесс определился бы неверно — а неверно определённый
// процесс это неверное правило маршрутизации, то есть трафик, ушедший не туда.
func findInode(entries []entry, local, remote netip.AddrPort) (uint64, bool) {
	for _, e := range entries {
		if sameEndpoint(e.local, local) && sameEndpoint(e.remote, remote) {
			return e.inode, true
		}
	}
	return 0, false
}

// sameEndpoint сравнивает концы, не придираясь к записи адреса.
//
// Ядро может показать петлю как ::ffff:127.0.0.1, а клиент прислать 127.0.0.1 — это один и
// тот же конец.
func sameEndpoint(a, b netip.AddrPort) bool {
	if a.Port() != b.Port() {
		return false
	}
	return a.Addr().Unmap() == b.Addr().Unmap()
}
