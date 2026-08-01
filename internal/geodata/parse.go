package geodata

import (
	"fmt"
	"net/netip"
	"strings"
)

// DomainKind — как сравнивать домен. Значения совпадают со схемой v2fly.
type DomainKind int

const (
	// DomainPlain — подстрока в имени.
	DomainPlain DomainKind = 0
	// DomainRegex — регулярное выражение.
	DomainRegex DomainKind = 1
	// DomainRoot — домен и его поддомены. Самый частый вид в списках.
	DomainRoot DomainKind = 2
	// DomainFull — точное совпадение.
	DomainFull DomainKind = 3
)

// Domain — одна запись списка доменов.
type Domain struct {
	Kind  DomainKind
	Value string
	// Attrs — пометки вида `@ads`, `@cn`. По ним списки делят на части: `geosite:google@ads`
	// означает «только рекламные домены гугла».
	Attrs []string
}

// Site — именованный список доменов.
type Site struct {
	Code    string
	Domains []Domain
}

// ParseSites разбирает geosite.dat.
func ParseSites(raw []byte) ([]Site, error) {
	r := newReader(raw)
	var out []Site

	for !r.done() {
		field, wire, err := r.tag()
		if err != nil {
			return nil, err
		}
		if field != 1 || wire != wireBytes {
			if err := r.skip(wire); err != nil {
				return nil, err
			}
			continue
		}
		entry, err := r.bytes()
		if err != nil {
			return nil, err
		}
		site, err := parseSite(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, site)
	}
	return out, nil
}

func parseSite(raw []byte) (Site, error) {
	r := newReader(raw)
	var site Site

	for !r.done() {
		field, wire, err := r.tag()
		if err != nil {
			return site, err
		}
		switch {
		case field == 1 && wire == wireBytes:
			b, err := r.bytes()
			if err != nil {
				return site, err
			}
			site.Code = strings.ToLower(string(b))
		case field == 2 && wire == wireBytes:
			b, err := r.bytes()
			if err != nil {
				return site, err
			}
			d, err := parseDomain(b)
			if err != nil {
				return site, err
			}
			site.Domains = append(site.Domains, d)
		default:
			if err := r.skip(wire); err != nil {
				return site, err
			}
		}
	}
	return site, nil
}

func parseDomain(raw []byte) (Domain, error) {
	r := newReader(raw)
	var d Domain

	for !r.done() {
		field, wire, err := r.tag()
		if err != nil {
			return d, err
		}
		switch {
		case field == 1 && wire == wireVarint:
			v, err := r.varint()
			if err != nil {
				return d, err
			}
			d.Kind = DomainKind(v)
		case field == 2 && wire == wireBytes:
			b, err := r.bytes()
			if err != nil {
				return d, err
			}
			d.Value = strings.ToLower(string(b))
		case field == 3 && wire == wireBytes:
			b, err := r.bytes()
			if err != nil {
				return d, err
			}
			attr, err := parseAttrKey(b)
			if err != nil {
				return d, err
			}
			if attr != "" {
				d.Attrs = append(d.Attrs, attr)
			}
		default:
			if err := r.skip(wire); err != nil {
				return d, err
			}
		}
	}
	return d, nil
}

// parseAttrKey достаёт имя пометки. Значение нам не нужно: в списках оно всегда `true`.
func parseAttrKey(raw []byte) (string, error) {
	r := newReader(raw)
	for !r.done() {
		field, wire, err := r.tag()
		if err != nil {
			return "", err
		}
		if field == 1 && wire == wireBytes {
			b, err := r.bytes()
			if err != nil {
				return "", err
			}
			return strings.ToLower(string(b)), nil
		}
		if err := r.skip(wire); err != nil {
			return "", err
		}
	}
	return "", nil
}

// IPSet — именованный список подсетей.
type IPSet struct {
	Code     string
	Prefixes []netip.Prefix
}

// ParseIPs разбирает geoip.dat.
func ParseIPs(raw []byte) ([]IPSet, error) {
	r := newReader(raw)
	var out []IPSet

	for !r.done() {
		field, wire, err := r.tag()
		if err != nil {
			return nil, err
		}
		if field != 1 || wire != wireBytes {
			if err := r.skip(wire); err != nil {
				return nil, err
			}
			continue
		}
		entry, err := r.bytes()
		if err != nil {
			return nil, err
		}
		set, err := parseIPSet(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, set)
	}
	return out, nil
}

func parseIPSet(raw []byte) (IPSet, error) {
	r := newReader(raw)
	var set IPSet

	for !r.done() {
		field, wire, err := r.tag()
		if err != nil {
			return set, err
		}
		switch {
		case field == 1 && wire == wireBytes:
			b, err := r.bytes()
			if err != nil {
				return set, err
			}
			set.Code = strings.ToLower(string(b))
		case field == 2 && wire == wireBytes:
			b, err := r.bytes()
			if err != nil {
				return set, err
			}
			prefix, err := parseCIDR(b)
			if err != nil {
				return set, err
			}
			if prefix.IsValid() {
				set.Prefixes = append(set.Prefixes, prefix)
			}
		default:
			if err := r.skip(wire); err != nil {
				return set, err
			}
		}
	}
	return set, nil
}

func parseCIDR(raw []byte) (netip.Prefix, error) {
	r := newReader(raw)
	var (
		ip     []byte
		bits   uint64
		hasLen bool
	)

	for !r.done() {
		field, wire, err := r.tag()
		if err != nil {
			return netip.Prefix{}, err
		}
		switch {
		case field == 1 && wire == wireBytes:
			b, err := r.bytes()
			if err != nil {
				return netip.Prefix{}, err
			}
			ip = b
		case field == 2 && wire == wireVarint:
			v, err := r.varint()
			if err != nil {
				return netip.Prefix{}, err
			}
			bits, hasLen = v, true
		default:
			if err := r.skip(wire); err != nil {
				return netip.Prefix{}, err
			}
		}
	}

	if !hasLen {
		return netip.Prefix{}, fmt.Errorf("geodata: подсеть без длины префикса")
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("geodata: адрес длиной %d байт", len(ip))
	}
	addr = addr.Unmap()
	if int(bits) > addr.BitLen() {
		return netip.Prefix{}, fmt.Errorf("geodata: длина префикса %d при адресе %s", bits, addr)
	}
	return netip.PrefixFrom(addr, int(bits)), nil
}
