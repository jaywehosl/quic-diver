package client

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/jaywehosl/quic-diver/internal/bundle"
	"github.com/jaywehosl/quic-diver/internal/hello"
	"github.com/jaywehosl/quic-diver/internal/node"
	"github.com/jaywehosl/quic-diver/internal/oplog"
)

// Откуда клиент узнаёт, куда подключаться.
//
// Обычный путь один — бандл: в нём вся сеть целиком, и именно он даёт клиенту пережить смерть
// узла. Отдельные флаги остаются для отладки: с ними удобно ткнуть в конкретный узел, не
// выпуская бандла ради одной проверки.

// network — всё, что клиент знает о сети до первого соединения.
type network struct {
	targets []node.Target
	// name — имя сети из бандла, для показа человеку.
	name      string
	self      hello.Identity
	hasEgress bool
	settings  oplog.Settings
	// genesis — отпечаток сети. Им проверяется, что снапшот пришёл от своих.
	genesis oplog.Fingerprint
	// fromBundle говорит, откуда это взялось: без бандла часть возможностей недоступна,
	// и молчать об этом нельзя.
	fromBundle bool
}

// resolveNetwork собирает сеть из бандла или из отдельных флагов.
func resolveNetwork(o Options, log *slog.Logger) (*network, error) {
	uri := strings.TrimSpace(o.Bundle)
	if uri == "" && o.BundleFile != "" {
		raw, err := os.ReadFile(o.BundleFile)
		if err != nil {
			return nil, fmt.Errorf("бандл: %w", err)
		}
		uri = strings.TrimSpace(string(raw))
	}

	if uri != "" {
		return fromBundle(uri, o.BundlePassword, log)
	}
	return fromFlags(o, log)
}

func fromBundle(uri, password string, log *slog.Logger) (*network, error) {
	b, err := bundle.Decode(uri, password)
	if err != nil {
		return nil, err
	}

	signer, err := signerOf(b.ClientKey)
	if err != nil {
		return nil, err
	}

	n := &network{
		self:       hello.Identity{Role: hello.RoleClient, ID: b.ClientID, Signer: signer},
		name:       b.Network,
		hasEgress:  b.HasEgress,
		settings:   b.Settings,
		genesis:    b.Genesis,
		fromBundle: true,
	}
	for _, in := range b.Ingress {
		n.targets = append(n.targets, node.Target{
			ID:        in.ID,
			Domain:    in.Domain,
			Endpoints: in.Endpoints,
			PublicKey: in.PublicKey,
		})
	}

	log.Info("бандл разобран", "network", b.Network, "genesis", b.Genesis.String()[:16],
		"client", b.ClientID, "входных узлов", len(n.targets), "есть выходные", b.HasEgress)
	return n, nil
}

func fromFlags(o Options, log *slog.Logger) (*network, error) {
	if o.NodeAddr == "" || o.ID == "" || o.KeyHex == "" {
		return nil, fmt.Errorf("нужен -bundle, либо -node, -id и -key вместе")
	}

	addr := o.NodeAddr
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	host, _, _ := strings.Cut(addr, ":")

	priv, err := hex.DecodeString(o.KeyHex)
	if err != nil {
		return nil, fmt.Errorf("ключ клиента: %w", err)
	}
	signer, err := signerOf(priv)
	if err != nil {
		return nil, err
	}
	nodePub, err := hex.DecodeString(o.NodeKey)
	if err != nil {
		return nil, fmt.Errorf("ключ узла: %w", err)
	}

	log.Warn("работаю без бандла: сеть — один узел, пережить его смерть нечем")
	return &network{
		targets: []node.Target{{
			ID:        host,
			Domain:    host,
			Endpoints: []string{addr},
			PublicKey: oplog.PublicKey(nodePub),
		}},
		self: hello.Identity{Role: hello.RoleClient, ID: o.ID, Signer: signer},
		// Без бандла узнать, есть ли в сети выходные узлы, неоткуда. Верим флагу человека:
		// он и так его выставляет руками.
		hasEgress: o.ViaExit,
	}, nil
}

func signerOf(priv []byte) (*oplog.MemorySigner, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ключ клиента должен быть %d байт, получено %d",
			ed25519.PrivateKeySize, len(priv))
	}
	return oplog.NewMemorySigner(ed25519.PrivateKey(priv))
}

// exceptions собирает адреса, которым туннель не писан.
//
// Мимо туннеля обязаны ходить **все** входные узлы, а не только тот, с кем связь сейчас:
// после обрыва гонка пойдёт заново, и завёрнутый в туннель узел окажется недостижим ровно
// тогда, когда он нужнее всего.
func exceptions(targets []node.Target) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, t := range targets {
		for _, e := range t.Endpoints {
			host, _, err := net.SplitHostPort(e)
			if err != nil {
				host = e
			}
			if addr, err := netip.ParseAddr(host); err == nil {
				out = append(out, addr.Unmap())
				continue
			}
			// Имя разрешается системным резолвером и до поднятия туннеля: внутри него
			// разрешать имя узла уже нечем. Ровно поэтому бандл несёт литералы.
			ips, err := net.LookupIP(host)
			if err != nil {
				return nil, fmt.Errorf("адрес узла %s: %w", host, err)
			}
			for _, ip := range ips {
				if addr, ok := netip.AddrFromSlice(ip); ok {
					out = append(out, addr.Unmap())
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("не удалось выяснить ни одного адреса входных узлов")
	}
	return out, nil
}
