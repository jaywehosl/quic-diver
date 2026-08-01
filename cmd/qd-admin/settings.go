package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/jaywehosl/quic-diver/internal/admin"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Параметры сети в журнале.
//
// Записываются целиком, как и правила: снимок либо согласован, либо нет. Флаг, который не
// назвали, берёт текущее значение — иначе смена одного числа сбрасывала бы остальные в ноль.

func cmdSettingsSet(args []string) error {
	fs := flag.NewFlagSet("settings set", flag.ContinueOnError)
	brutalUp := fs.Int("brutal-up", -1, "потолок BRUTAL на отдачу клиента, Мбит/с; 0 — выключить")
	brutalDown := fs.Int("brutal-down", -1, "потолок BRUTAL на приём клиента, Мбит/с; 0 — выключить")
	brutalMesh := fs.Int("brutal-mesh", -1, "потолок BRUTAL между узлами, Мбит/с; 0 — выключить")
	dnsPrimary := fs.String("dns-primary", "", "первичный резолвер узла, host:port")
	dnsSecondary := fs.String("dns-secondary", "", "вторичный резолвер узла, host:port")
	dnsCache := fs.Int("dns-cache", -1, "потолок числа записей в кеше имён; 0 — без кеша")
	dnsMinTTL := fs.Int("dns-min-ttl", -1, "нижняя граница времени жизни ответа, секунды")
	dnsMaxTTL := fs.Int("dns-max-ttl", -1, "верхняя граница времени жизни ответа, секунды")

	st, keys, err := workdir(fs, args)
	if err != nil {
		return err
	}
	defer st.Close()

	s := st.State().Settings()
	setInt(&s.BrutalUpMbps, *brutalUp)
	setInt(&s.BrutalDownMbps, *brutalDown)
	setInt(&s.BrutalMeshMbps, *brutalMesh)
	setInt(&s.DNSCacheEntries, *dnsCache)
	setInt(&s.DNSMinTTL, *dnsMinTTL)
	setInt(&s.DNSMaxTTL, *dnsMaxTTL)
	if *dnsPrimary != "" {
		s.DNSPrimary = *dnsPrimary
	}
	if *dnsSecondary != "" {
		s.DNSSecondary = *dnsSecondary
	}

	session, err := admin.NewSession(st, keys, oplog.ScopeOperator)
	if err != nil {
		return err
	}
	if _, err := session.Submit(oplog.KindSettingsSet, s); err != nil {
		return err
	}

	printSettings(s)
	if s.BrutalUpMbps > 0 || s.BrutalDownMbps > 0 || s.BrutalMeshMbps > 0 {
		fmt.Println("\nBRUTAL не снижает скорость при потерях (решение 006).")
		fmt.Println("Потолок обязан соответствовать реальному каналу: выше — только вред,")
		fmt.Println("лишние пакеты не доедут, но забьют очередь и испортят задержку себе же.")
	}
	fmt.Println("\nЖурнал разойдётся по узлам сам; клиенты получат числа со следующим бандлом.")
	return nil
}

// cmdDNSFlush просит узлы очистить кеш имён.
//
// Записью, а не командой по сети: узел, лежавший в момент команды, поднявшись, увидит метку
// в журнале и выполнит сброс сам. Команда по сети до него бы не добралась вовсе.
func cmdDNSFlush(args []string) error {
	fs := flag.NewFlagSet("dns flush", flag.ContinueOnError)
	st, keys, err := workdir(fs, args)
	if err != nil {
		return err
	}
	defer st.Close()

	s := st.State().Settings()
	s.DNSFlushAt = time.Now().Unix()

	session, err := admin.NewSession(st, keys, oplog.ScopeOperator)
	if err != nil {
		return err
	}
	if _, err := session.Submit(oplog.KindSettingsSet, s); err != nil {
		return err
	}

	fmt.Println("кеш имён будет сброшен на всех узлах, как только запись до них доедет")
	fmt.Println("соединения при этом не рвутся: следующий запрос просто пойдёт к резолверу заново")
	return nil
}

func cmdSettingsShow(args []string) error {
	fs := flag.NewFlagSet("settings show", flag.ContinueOnError)
	st, _, err := workdir(fs, args)
	if err != nil {
		return err
	}
	defer st.Close()

	printSettings(st.State().Settings())
	return nil
}

func printSettings(s oplog.Settings) {
	fmt.Println("параметры сети:")
	fmt.Printf("  BRUTAL: отдача клиента %s, приём клиента %s, между узлами %s\n",
		mbps(s.BrutalUpMbps), mbps(s.BrutalDownMbps), mbps(s.BrutalMeshMbps))
	fmt.Printf("  резолверы: %s / %s\n", orNone(s.DNSPrimary), orNone(s.DNSSecondary))
	fmt.Printf("  кеш имён: %s, TTL от %s до %s\n",
		entries(s.DNSCacheEntries), seconds(s.DNSMinTTL), seconds(s.DNSMaxTTL))
}

// setInt меняет значение, только если флаг называли: -1 означает «не трогать».
func setInt(dst *int, v int) {
	if v >= 0 {
		*dst = v
	}
}

func mbps(v int) string {
	if v <= 0 {
		return "выключен"
	}
	return fmt.Sprintf("%d Мбит/с", v)
}

func entries(v int) string {
	if v <= 0 {
		return "выключен"
	}
	return fmt.Sprintf("%d записей", v)
}

func seconds(v int) string {
	if v <= 0 {
		return "как отдали"
	}
	return fmt.Sprintf("%d с", v)
}

func orNone(s string) string {
	if s == "" {
		return "по умолчанию"
	}
	return s
}
