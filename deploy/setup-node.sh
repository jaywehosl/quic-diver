#!/usr/bin/env bash
# Развёртывание узла QUIC Diver.
#
# Принимает ключ развёртывания, выданный приложением, и доводит машину до работающего узла:
# пакеты, пользователь, каталоги, конфиг, юнит systemd, старт. В конце печатает код узла — его
# человек вводит в приложении, чтобы то убедилось, что говорит с этой машиной, а не с тем, кто
# перехватил домен.
#
# Чего скрипт НЕ делает, хотя это кажется его работой:
#
#   Не занимается сертификатом. Узел держит :80 постоянно — он и так отдаёт там перенаправление,
#   как всякий сайт, — и выпускает сертификат сам через ACME при первом запуске, дальше обновляет
#   без чьего-либо участия. Отдельный certbot со своей политикой обновления и захватом порта тут
#   лишний и будет мешать.
#
#   Не пишет записей в журнал. Записи подписываются ключом владельца, а его на сервере нет и быть
#   не должно — иначе вскрывший сервер забирает сеть себе. Узел создаёт себе пару при первом
#   запуске и ждёт, пока владелец впишет его в журнал со своего устройства.
#
# Использование:
#   ./setup-node.sh --key qdnode:… [--binary /путь/к/qd-node] [--email you@example.org]
#
set -euo pipefail

REPO="jaywehosl/quic-diver"
BIN=/usr/local/bin/qd-node
CONFIG=/etc/qdiver/node.toml
UNIT=/etc/systemd/system/qd-node.service

KEY=""
BINARY=""
EMAIL=""
SKIP_CHECKS=0

usage() {
	cat >&2 <<'EOF'
setup-node.sh --key qdnode:…

  --key <ключ>       ключ развёртывания из приложения (обязателен)
  --binary <путь>    взять готовый двоичный файл вместо загрузки из релизов
  --email <почта>    почта для Let's Encrypt, необязательно
  --skip-checks      не проверять домен и порты (только если знаешь, зачем)
EOF
	exit 2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--key) KEY="${2:-}"; shift 2 ;;
	--binary) BINARY="${2:-}"; shift 2 ;;
	--email) EMAIL="${2:-}"; shift 2 ;;
	--skip-checks) SKIP_CHECKS=1; shift ;;
	-h|--help) usage ;;
	*) echo "неизвестный аргумент: $1" >&2; usage ;;
	esac
done

[ -n "$KEY" ] || usage
[ "$(id -u)" = "0" ] || { echo "нужен root" >&2; exit 1; }

say() { printf '\n== %s\n' "$1"; }
die() { printf '\nошибка: %s\n' "$1" >&2; exit 1; }

# ─── пакеты ──────────────────────────────────────────────────────────────────────────────────
# Узлу самому не нужно ничего: он статический. Всё нижеперечисленное нужно этому скрипту —
# скачать файл, проверить сумму, посмотреть, куда указывает домен.
say "пакеты"
if command -v apt-get >/dev/null 2>&1; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq curl ca-certificates dnsutils >/dev/null
elif command -v dnf >/dev/null 2>&1; then
	dnf install -y -q curl ca-certificates bind-utils >/dev/null
elif command -v yum >/dev/null 2>&1; then
	yum install -y -q curl ca-certificates bind-utils >/dev/null
else
	echo "менеджер пакетов не опознан — считаю, что curl и dig уже есть"
fi

# ─── двоичный файл ───────────────────────────────────────────────────────────────────────────
say "двоичный файл"
if [ -n "$BINARY" ]; then
	[ -f "$BINARY" ] || die "нет файла $BINARY"
	install -m 0755 "$BINARY" "$BIN"
	echo "поставлен из $BINARY"
else
	arch="$(uname -m)"
	case "$arch" in
	x86_64) goarch=amd64 ;;
	aarch64|arm64) goarch=arm64 ;;
	*) die "неизвестная архитектура $arch" ;;
	esac

	tag="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
		sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
	[ -n "$tag" ] || die "релизов пока нет — собери двоичный файл сам и передай --binary"

	url="https://github.com/$REPO/releases/download/$tag/qd-node-linux-$goarch"
	echo "качаю $tag ($goarch)"
	curl -fsSL "$url" -o /tmp/qd-node.new || die "не скачалось: $url"

	# Сумма из релиза: файл едет по сети, и подменить его по дороге проще, чем кажется.
	if curl -fsSL "$url.sha256" -o /tmp/qd-node.sha256 2>/dev/null; then
		want="$(cut -d' ' -f1 /tmp/qd-node.sha256)"
		got="$(sha256sum /tmp/qd-node.new | cut -d' ' -f1)"
		[ "$want" = "$got" ] || die "контрольная сумма не сошлась: $got вместо $want"
		echo "сумма сошлась"
	else
		echo "предупреждение: суммы для релиза нет, ставлю как есть"
	fi
	install -m 0755 /tmp/qd-node.new "$BIN"
	rm -f /tmp/qd-node.new /tmp/qd-node.sha256
fi

# ─── пользователь и каталоги ─────────────────────────────────────────────────────────────────
say "пользователь и каталоги"
id -u qdiver >/dev/null 2>&1 ||
	useradd --system --home-dir /var/lib/qdiver --shell /usr/sbin/nologin qdiver
install -d -o qdiver -g qdiver -m 0700 /var/lib/qdiver /var/lib/qdiver/certs
install -d -m 0755 /etc/qdiver

# ─── настройки ───────────────────────────────────────────────────────────────────────────────
# Ключ разбирает сам узел: внутри gzip под base64 с контрольной суммой, и писать этот разбор
# на shell значило бы завести зависимость от jq и чинить её при каждой правке формата.
say "настройки"
"$BIN" -deploy "$KEY" -config "$CONFIG" || die "ключ развёртывания не принят"

if [ -n "$EMAIL" ]; then
	sed -i "s|^acme_email = .*|acme_email = \"$EMAIL\"|" "$CONFIG"
fi
chown root:qdiver "$CONFIG"
chmod 0640 "$CONFIG"

DOMAIN="$(sed -n 's/^domain *= *"\(.*\)"/\1/p' "$CONFIG")"
[ -n "$DOMAIN" ] || die "в настройках нет домена"

# ─── проверки до старта ──────────────────────────────────────────────────────────────────────
# Обе беды ниже выглядят одинаково — «узел не работает», — а причины разные и лечатся в разных
# местах. Сказать о них до старта дешевле, чем разбирать потом по журналам.
if [ "$SKIP_CHECKS" = "0" ]; then
	say "проверки"

	mine="$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || echo '')"
	resolved="$(dig +short A "$DOMAIN" 2>/dev/null | tail -n1 || echo '')"
	if [ -n "$mine" ] && [ -n "$resolved" ]; then
		if [ "$mine" = "$resolved" ]; then
			echo "домен $DOMAIN указывает сюда ($mine)"
		else
			echo "предупреждение: $DOMAIN указывает на $resolved, а этот сервер $mine"
			echo "  сертификат не выпустится, пока запись не поправлена (за NAT это нормально)"
		fi
	else
		echo "предупреждение: не вышло сверить домен с адресом сервера"
	fi

	for port in 80 443; do
		if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$port\$"; then
			holder="$(ss -lntp 2>/dev/null | grep -E "[:.]$port\b" | head -n1 || true)"
			echo "предупреждение: порт $port уже занят — узел не поднимется"
			[ -n "$holder" ] && echo "  $holder"
		else
			echo "порт $port свободен"
		fi
	done
fi

# ─── служба ──────────────────────────────────────────────────────────────────────────────────
say "служба"
unit_src="$(dirname "$0")/qd-node.service"
if [ -f "$unit_src" ]; then
	install -m 0644 "$unit_src" "$UNIT"
else
	curl -fsSL "https://raw.githubusercontent.com/$REPO/main/deploy/qd-node.service" -o "$UNIT" ||
		die "не удалось получить юнит systemd"
fi

# QUIC упирается в приёмный буфер ядра куда раньше, чем в канал: значения по умолчанию малы
# настолько, что quic-go пишет об этом в журнал при каждом запуске.
cat > /etc/sysctl.d/99-qdiver.conf <<'EOF'
net.core.rmem_max = 7500000
net.core.wmem_max = 7500000
EOF
sysctl -q -p /etc/sysctl.d/99-qdiver.conf || true

systemctl daemon-reload
systemctl enable --now qd-node >/dev/null

sleep 2
systemctl is-active --quiet qd-node || {
	echo "служба не поднялась:" >&2
	journalctl -u qd-node -n 20 --no-pager >&2 || true
	exit 1
}

# ─── итог ────────────────────────────────────────────────────────────────────────────────────
# Ключ к этому моменту уже создан службой, так что здесь только чтение. runuser есть не везде —
# на такой случай читаем от root: файл принадлежит qdiver, но root его и так прочтёт.
show_key() {
	if command -v runuser >/dev/null 2>&1; then
		runuser -u qdiver -- "$BIN" -config "$CONFIG" -show-key 2>/dev/null
	else
		"$BIN" -config "$CONFIG" -show-key 2>/dev/null
	fi
}
CODE="$(show_key | sed -n 's/^code=//p')"

cat <<EOF

== узел поднят

домен:  $DOMAIN
служба: systemctl status qd-node
журнал: journalctl -u qd-node -f

Код узла: $CODE

Введи его в приложении на экране включения узла. Приложение спросит узел по сети, сверит код с
этим и, если сошлось, подпишет запись и отдаст журнал. Сертификат домена доказывает только
владение доменом — код доказывает, что это именно та машина, которую ты сейчас настроил.

До приёма журнала узел отдаёт всем страницу-заглушку. Это не поломка: узел, не включённый в
сеть, ничем не отличается от обычного сайта, и отличаться не должен.
EOF
