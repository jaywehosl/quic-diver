package ownerlog

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/jaywehosl/quic-diver/internal/node"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Включение узла в сеть (решение 007 §3, шаг 7).
//
// # Порядок
//
//  1. Человек запустил на сервере скрипт с ключом развёртывания. Узел поднялся: сертификат
//     выпустил, порты слушает, журнала не имеет — то есть выглядит обычным сайтом.
//  2. Приложение спрашивает узел, кто он. Тот называет имя, домен и свой публичный ключ.
//     Отвечает только узел без журнала: включённый в сеть на этот вопрос молчит.
//  3. Владелец подписывает запись об узле — своим ключом, у себя на устройстве.
//  4. Приложение заливает журнал целиком. Узел сверяет отпечаток генезиса со своим конфигом
//     и с этой минуты в сети.
//
// # Почему ключ узла спрашивают, а не вводят
//
// Ключевая пара узла рождается на сервере при первом запуске, и знать её больше некому.
// Значит либо человек переносит шестьдесят четыре знака руками — и однажды ошибётся так, что
// никто не заметит до первого подключения, — либо приложение спрашивает сама. Спрашивать
// безопасно: ключ публичный, а путь, по которому его отдают, работает лишь пока узел пуст.

// ErrWrongCode означает, что узел на том конце назвался не тем кодом.
//
// Отдельная ошибка, потому что обращаться с ней надо иначе, чем с «узел ещё не поднялся»:
// повторять попытки бессмысленно и опасно. Каждый повтор — это ещё одна попытка угадать код
// для того, кто перехватил домен, а поводов ждать, что ответ изменится, нет: код считается из
// ключа, а ключ у узла один.
var ErrWrongCode = errors.New("ownerlog: код узла не совпал")

// AdoptParams — что нужно, чтобы включить узел.
type AdoptParams struct {
	// Addr — куда стучаться: host либо host:port. Без порта берётся 443.
	Addr string
	// Roles — ingress, egress или обе.
	Roles []string
	// Tags — подписи для человека. На маршрутизацию не влияют.
	Tags []string
	// Endpoints — адреса узла литералами, для клиентов. Пустой означает «взять из Addr»:
	// именно по нему мы сейчас достучались, значит он рабочий.
	Endpoints []string
	// Code — код узла, напечатанный скриптом развёртывания у человека в терминале.
	//
	// Пустой означает, что сверки нет: узел берётся на веру по TLS. Так работает добавление
	// узла в уже живую сеть, где журнал приезжает соседу от соседа, а не с телефона.
	Code string
	// OwnerKey — ключ владельца, которым подписывается запись.
	OwnerKey ed25519.PrivateKey
	// Now подменяет часы в тестах.
	Now func() time.Time
	// Insecure отключает проверку сертификата. Нужно ровно в одном случае: узел поднят на
	// домене, чей сертификат ещё не выпущен, — ACME отвечает не мгновенно.
	Insecure bool
}

// Adopt включает узел в сеть.
//
// Журнал меняется только при удаче: запись добавляется после того, как узел её принял. Иначе
// неудачная попытка оставляла бы в журнале узел, которого нет, и он попадал бы клиентам в
// снапшот — те честно ходили бы в никуда.
func (j *Journal) Adopt(ctx context.Context, p AdoptParams) (oplog.Node, error) {
	if j.Genesis().IsZero() {
		return oplog.Node{}, ErrNoGenesis
	}
	if len(p.OwnerKey) != ed25519.PrivateKeySize {
		return oplog.Node{}, errors.New("ownerlog: не задан ключ владельца")
	}
	if len(p.Roles) == 0 {
		return oplog.Node{}, errors.New("ownerlog: не задана роль узла")
	}
	now := p.Now
	if now == nil {
		now = time.Now
	}

	addr := strings.TrimSpace(p.Addr)
	if addr == "" {
		return oplog.Node{}, errors.New("ownerlog: не задан адрес узла")
	}
	host, port := addr, "443"
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host, port = h, p
	} else {
		addr = net.JoinHostPort(addr, port)
	}

	tlsConf := &tls.Config{ServerName: host, InsecureSkipVerify: p.Insecure}

	intro, err := node.Introduce(ctx, addr, tlsConf)
	if err != nil {
		return oplog.Node{}, err
	}

	// Сверка кода. TLS доказывает владение доменом, а не принадлежность к нашей сети: тот, кто
	// на пять минут получил власть над DNS, выпишет себе сертификат и ответит своим ключом.
	// Код напечатан на самом сервере, у человека в терминале, — подделавшему ответ его неоткуда
	// узнать.
	if strings.TrimSpace(p.Code) != "" && !node.CodeMatches(intro.PublicKey, p.Code) {
		return oplog.Node{}, fmt.Errorf("%w: узел назвался кодом %s, введён %s",
			ErrWrongCode, node.Code(intro.PublicKey), node.NormalizeCode(p.Code))
	}

	endpoints := p.Endpoints
	if len(endpoints) == 0 {
		endpoints, err = resolveEndpoints(ctx, host, port)
		if err != nil {
			return oplog.Node{}, err
		}
	}

	record := oplog.Node{
		ID:        intro.ID,
		PublicKey: intro.PublicKey,
		Roles:     p.Roles,
		Tags:      p.Tags,
		Domain:    intro.Domain,
		Endpoints: endpoints,
	}

	signer, err := oplog.NewMemorySigner(p.OwnerKey)
	if err != nil {
		return oplog.Node{}, err
	}
	op, err := oplog.NewOp(signer, oplog.KindNodeAdd, j.Next(signer.KeyID()), now(), record)
	if err != nil {
		return oplog.Node{}, fmt.Errorf("ownerlog: запись об узле: %w", err)
	}

	// Запись сначала примеряется к копии состояния — тем же кодом, каким её проверит узел.
	// Так негодная запись не попадёт в журнал даже на мгновение.
	probe, err := j.probe(op)
	if err != nil {
		return oplog.Node{}, err
	}

	journal, err := probe.Bytes()
	if err != nil {
		return oplog.Node{}, err
	}
	if err := node.PushLog(ctx, addr, tlsConf, bytesReader(journal)); err != nil {
		return oplog.Node{}, err
	}

	if _, err := j.Append(op); err != nil {
		return oplog.Node{}, err
	}
	return record, nil
}

// resolveEndpoints превращает имя узла в адреса-литералы.
//
// Литералы, а не имя, потому что этот список едет клиенту, а клиент поднимает по нему исключения
// маршрутизации — до включения туннеля. Внутри туннеля разрешать имя узла уже нечем: служба имён
// работает через сам туннель, и первый же запрос ушёл бы в него, то есть в никуда.
//
// Берутся все адреса сразу, и v4, и v6: у узла бывает и то и другое, а рабочим оказывается не
// всегда первый в списке — гонка выясняет это сама.
func resolveEndpoints(ctx context.Context, host, port string) ([]string, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []string{net.JoinHostPort(ip.String(), port)}, nil
	}

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("ownerlog: адреса узла %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("ownerlog: у %s нет ни одного адреса", host)
	}

	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.JoinHostPort(a.Unmap().String(), port))
	}
	return out, nil
}

// probe собирает копию журнала с добавленной записью, не трогая исходный.
func (j *Journal) probe(op *oplog.Op) (*Journal, error) {
	raw, err := j.Bytes()
	if err != nil {
		return nil, err
	}
	copyOf, err := Read(bytesReader(raw))
	if err != nil {
		return nil, err
	}
	if _, err := copyOf.Append(op); err != nil {
		return nil, err
	}
	return copyOf, nil
}
