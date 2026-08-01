package client

import (
	"os"
	"testing"
)

// pipeFD отдаёт живой дескриптор и способ узнать, закрыт ли он.
func pipeFD(t *testing.T) (int, func() bool) {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("труба: %v", err)
	}
	t.Cleanup(func() {
		r.Close()
		// Второй Close по уже закрытому вернёт ошибку — она здесь не важна.
		_ = w.Close()
	})

	fd := int(w.Fd())
	closed := func() bool {
		// Запись в закрытый дескриптор не проходит. Живой примет байт: труба не читается,
		// но её буфер вмещает куда больше одного байта.
		_, err := os.NewFile(uintptr(fd), "probe").Write([]byte{0})
		return err != nil
	}
	return fd, closed
}

// Главное свойство: до туннеля дело не дошло — дескриптор закрыт.
//
// Иначе интерфейс живёт вечно: приложение сняло с него владение и больше о нём не знает, а
// человек видит значок VPN при снятом туннеле.
func TestGuardClosesUnusedDescriptor(t *testing.T) {
	fd, closed := pipeFD(t)

	g := newFDGuard(fd, quiet())
	if closed() {
		t.Fatal("дескриптор закрылся сам, до сторожа")
	}

	g.close()
	if !closed() {
		t.Fatal("сторож не закрыл ничей дескриптор")
	}
}

// Туннель принял дескриптор — сторож обязан молчать. Закрыть его вторым хуже утечки:
// двойное закрытие на Android ловит fdsan и убивает процесс целиком.
func TestGuardKeepsHandsOffAfterTaken(t *testing.T) {
	fd, closed := pipeFD(t)

	g := newFDGuard(fd, quiet())
	g.taken()
	g.close()

	if closed() {
		t.Fatal("сторож закрыл дескриптор, отданный туннелю")
	}
}

// Закрывать дважды нельзя и самому сторожу: defer может сработать после явного вызова.
func TestGuardClosesOnlyOnce(t *testing.T) {
	fd, closed := pipeFD(t)

	g := newFDGuard(fd, quiet())
	g.close()
	if !closed() {
		t.Fatal("первый вызов не закрыл")
	}
	// Второй раз обязан пройти молча и ничего не трогать.
	g.close()
}

// Клиент, создающий интерфейс сам, дескриптора извне не получает — сторожить нечего.
func TestGuardWithoutDescriptor(t *testing.T) {
	newFDGuard(0, quiet()).close()
	var nothing *fdGuard
	nothing.taken()
	nothing.close()
}
