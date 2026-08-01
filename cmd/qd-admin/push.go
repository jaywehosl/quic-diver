package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/jaywehosl/quic-diver/internal/node"
)

// cmdPush заливает журнал в свежий узел прямо по сети.
//
// Заменяет связку export → scp → qd-node -import → systemctl restart: узел принимает журнал на
// ходу и перезапуска не требует. Работает ровно один раз в жизни узла — пока журнал у него
// пуст (решение 007 §3.3).
func cmdPush(args []string) error {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	insecure := fs.Bool("insecure", false, "не проверять сертификат узла (только для узла без домена)")
	timeout := fs.Duration("timeout", 30*time.Second, "срок на весь залив")
	st, _, err := workdir(fs, args)
	if err != nil {
		return err
	}
	defer st.Close()

	if fs.NArg() == 0 {
		return fmt.Errorf("не задан адрес узла (например qdiver7.example:443)")
	}
	addr := fs.Arg(0)
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Порт не назвали — узел слушает свой обычный, тот же, что и всякий сайт.
		host, addr = addr, net.JoinHostPort(addr, "443")
	}

	// Журнал собирается в память целиком: он мал, а поток пришлось бы перематывать при
	// повторе, чего io.Reader не обещает.
	var journal bytes.Buffer
	if err := st.Export(&journal); err != nil {
		return err
	}
	if journal.Len() == 0 {
		return fmt.Errorf("журнал пуст: сначала qd-admin init")
	}

	tlsConf := &tls.Config{ServerName: host, InsecureSkipVerify: *insecure}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := node.PushLog(ctx, addr, tlsConf, &journal); err != nil {
		return err
	}

	n, _ := st.Len()
	fmt.Printf("журнал залит в %s: записей %d\nсеть: %s\nотпечаток: %s\n",
		addr, n, st.State().Network(), st.State().Genesis())
	return nil
}
