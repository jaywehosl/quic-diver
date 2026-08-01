//go:build linux

package procmatch

import (
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Поиск процесса на Linux.
//
// Двумя шагами: в /proc/net/tcp находим инод сокета, затем ищем процесс, у которого этот
// инод открыт. Второй шаг — обход /proc/*/fd, и он дорогой: на машине с сотней процессов это
// тысячи чтений ссылок. Поэтому результат кешируется по иноду, а сам обход делается только
// тогда, когда в кеше промах.

// cacheTTL — сколько живёт запись кеша.
//
// Инод сокета уникален и переиспользуется ядром только после закрытия, так что ошибиться
// кеш может лишь в одном случае: соединение закрылось, инод достался другому процессу, а мы
// ещё помним старое имя. Минуты хватает, чтобы этого практически не случалось, и вполне
// достаточно, чтобы обход /proc не повторялся на каждый поток.
const cacheTTL = time.Minute

// linuxFinder ищет процессы через /proc.
type linuxFinder struct {
	// root — корень procfs. Подменяется в тестах.
	root string

	mu    sync.Mutex
	cache map[uint64]cached
}

type cached struct {
	name string
	at   time.Time
}

// New создаёт искатель для этой платформы.
func New() Finder {
	return &linuxFinder{root: "/proc", cache: make(map[uint64]cached)}
}

func (f *linuxFinder) Lookup(local, remote netip.AddrPort) (string, error) {
	inode, ok := f.inodeOf(local, remote)
	if !ok {
		return "", ErrNotFound
	}

	f.mu.Lock()
	if c, ok := f.cache[inode]; ok && time.Since(c.at) < cacheTTL {
		f.mu.Unlock()
		return c.name, nil
	}
	f.mu.Unlock()

	name, err := f.processOf(inode)
	if err != nil {
		return "", err
	}

	f.mu.Lock()
	f.cache[inode] = cached{name: name, at: time.Now()}
	f.mu.Unlock()
	return name, nil
}

// inodeOf ищет инод сокета в таблицах ядра.
func (f *linuxFinder) inodeOf(local, remote netip.AddrPort) (uint64, bool) {
	// Обе таблицы: соединение на петле может оказаться и в v4, и в v6 — зависит от того,
	// как приложение открыло сокет.
	for _, name := range []string{"net/tcp", "net/tcp6"} {
		file, err := os.Open(filepath.Join(f.root, name))
		if err != nil {
			continue
		}
		entries, err := parseNetTable(file)
		file.Close()
		if err != nil {
			continue
		}
		if inode, ok := findInode(entries, local, remote); ok {
			return inode, true
		}
	}
	return 0, false
}

// processOf ищет процесс, у которого открыт этот инод.
func (f *linuxFinder) processOf(inode uint64) (string, error) {
	want := "socket:[" + strconv.FormatUint(inode, 10) + "]"

	dirs, err := os.ReadDir(f.root)
	if err != nil {
		return "", err
	}

	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue // не процесс
		}

		fdDir := filepath.Join(f.root, d.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			// Чужой процесс без прав доступа — обычное дело, идём дальше.
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || link != want {
				continue
			}
			return f.nameOf(pid), nil
		}
	}
	return "", ErrNotFound
}

// nameOf возвращает имя процесса.
//
// Берётся из comm — там короткое имя без пути, ровно то, что человек пишет в правиле.
// Если comm недоступен, пробуем ссылку на исполняемый файл.
func (f *linuxFinder) nameOf(pid int) string {
	dir := filepath.Join(f.root, strconv.Itoa(pid))

	if raw, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		if name := strings.TrimSpace(string(raw)); name != "" {
			return name
		}
	}
	if link, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		return filepath.Base(link)
	}
	return ""
}
