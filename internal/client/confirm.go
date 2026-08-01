package client

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Режим `ask` для обновления баз.
//
// Спросить можно только тогда, когда есть кого спрашивать: клиент, запущенный человеком в
// терминале, вопрос увидит, а служба под systemd — нет. Задавать вопрос в никуда хуже, чем
// не задавать: клиент встал бы намертво, ожидая ответа, которого не будет.
//
// Поэтому: терминал есть — спрашиваем; терминала нет — качаем и говорим об этом. Свежие базы
// важнее задержки, а человек, которому это не нравится, ставит `-geo-update off`.

// confirmUpdate спрашивает разрешение на обновление баз.
func confirmUpdate(installed, latest string) bool {
	if !interactive() {
		fmt.Fprintf(os.Stderr,
			"qd-client: вышли свежие базы (%s → %s), спросить некого — качаю.\n"+
				"           Не нужно спрашивать вовсе: -geo-update off\n",
			shown(installed), latest)
		return true
	}

	fmt.Printf("Вышли свежие базы geosite/geoip: %s → %s. Обновить? [Y/n] ",
		shown(installed), latest)

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		// Ввод кончился, не начавшись: считаем это согласием — ровно так же, как если бы
		// терминала не было вовсе.
		fmt.Println()
		return true
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "n", "no", "н", "нет":
		return false
	default:
		return true
	}
}

// interactive говорит, есть ли живой терминал по обе стороны разговора.
func interactive() bool {
	return isTerminal(os.Stdin) && isTerminal(os.Stdout)
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func shown(version string) string {
	if version == "" {
		return "нет"
	}
	return version
}
