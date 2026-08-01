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
FORCE=0

usage() {
	cat >&2 <<'EOF'
setup-node.sh --key qdnode:…

  --key <ключ>       ключ развёртывания из приложения (обязателен)
  --binary <путь>    взять готовый двоичный файл вместо загрузки из релизов
  --email <почта>    почта для Let's Encrypt, необязательно
  --force            развернуть поверх уже настроенного узла: служба останавливается,
                     прежние настройки и журнал убираются в резервную копию
  --skip-checks      не проверять домен и порты — узел за NAT либо порты заняты намеренно
EOF
	exit 2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--key) KEY="${2:-}"; shift 2 ;;
	--binary) BINARY="${2:-}"; shift 2 ;;
	--email) EMAIL="${2:-}"; shift 2 ;;
	--force) FORCE=1; shift ;;
	--skip-checks) SKIP_CHECKS=1; shift ;;
	-h|--help) usage ;;
	*) echo "неизвестный аргумент: $1" >&2; usage ;;
	esac
done

[ -n "$KEY" ] || usage
[ "$(id -u)" = "0" ] || { echo "нужен root" >&2; exit 1; }

say() { printf '\n== %s\n' "$1"; }

# Что откатить, если дальше не пойдёт. Заполняется по ходу: скрипт может упасть на середине,
# и оставлять после себя полунастроенный узел нельзя — при следующем запуске он выглядел бы
# настроенным и мешал бы сам себе.
ROLLBACK=""
rollback_add() { ROLLBACK="$1 $ROLLBACK"; }

die() {
	printf '\nошибка: %s\n' "$1" >&2
	if [ -n "$ROLLBACK" ]; then
		printf 'откатываю изменения\n' >&2
		for step in $ROLLBACK; do
			case "$step" in
			service) systemctl stop qd-node 2>/dev/null || true
			         systemctl disable qd-node 2>/dev/null || true
			         rm -f "$UNIT"; systemctl daemon-reload 2>/dev/null || true ;;
			config)  rm -f "$CONFIG" ;;
			binary)  rm -f "$BIN" ;;
			esac
		done
	fi
	exit 1
}

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

# ─── что уже стоит ───────────────────────────────────────────────────────────────────────────
# Разбираемся с прежней установкой до того, как что-то трогать. Иначе выходит так: скрипт
# поставил бинарь, переписал часть файлов и упёрся в чужой конфиг — а машина осталась в
# состоянии, которое ни туда, ни сюда.
if [ -f "$CONFIG" ] || systemctl list-unit-files qd-node.service >/dev/null 2>&1; then
	if [ "$FORCE" = "0" ]; then
		cat >&2 <<EOF

ошибка: на этой машине уже есть узел

  настройки: $CONFIG
  служба:    $(systemctl is-active qd-node 2>/dev/null || echo 'нет')

Развернуть поверх — ключом --force: служба остановится, прежние настройки и журнал уйдут в
резервную копию рядом с ними. Ключевая пара узла при этом сохраняется, а значит сохраняется и
его код: пара принадлежит машине, а не сети.
EOF
		exit 1
	fi

	say "прежняя установка"
	systemctl stop qd-node 2>/dev/null || true
	systemctl disable qd-node 2>/dev/null || true

	stamp="$(date +%Y%m%d-%H%M%S)"
	if [ -f "$CONFIG" ]; then
		mv "$CONFIG" "$CONFIG.$stamp.bak"
		echo "прежние настройки: $CONFIG.$stamp.bak"
	fi
	# Журнал прежней сети убирается: узел с чужим журналом не примет наш — отпечаток не сойдётся,
	# и сообщение об этом человек увидит уже потом, в логе службы, где его никто не ищет.
	if [ -f /var/lib/qdiver/oplog.db ]; then
		mkdir -p "/var/lib/qdiver/old-$stamp"
		mv /var/lib/qdiver/oplog.db* "/var/lib/qdiver/old-$stamp/" 2>/dev/null || true
		chown -R qdiver:qdiver "/var/lib/qdiver/old-$stamp"
		echo "прежний журнал: /var/lib/qdiver/old-$stamp/"
	fi
fi

# ─── двоичный файл ───────────────────────────────────────────────────────────────────────────
say "двоичный файл"
if [ -n "$BINARY" ]; then
	[ -f "$BINARY" ] || die "нет файла $BINARY"
	[ -f "$BIN" ] || rollback_add binary
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
#
# Сначала во временный файл: домен нужен проверкам, а проверки идут до того, как что-то станет
# настоящим. Иначе выходит то, что и вышло при первой обкатке — узел разворачивается на домен,
# который на него не указывает, скрипт про это говорит и как ни в чём не бывало доходит до
# конца, выдавая код от узла, к которому не подключиться.
say "настройки"
TMP_CONFIG="$(mktemp)"
"$BIN" -deploy "$KEY" -config "$TMP_CONFIG" || { rm -f "$TMP_CONFIG"; die "ключ развёртывания не принят"; }

DOMAIN="$(sed -n 's/^domain *= *"\(.*\)"/\1/p' "$TMP_CONFIG")"
[ -n "$DOMAIN" ] || { rm -f "$TMP_CONFIG"; die "в настройках нет домена"; }

# ─── проверки до старта ──────────────────────────────────────────────────────────────────────
# Обе беды ниже выглядят одинаково — «узел не работает», — а причины разные и лечатся в разных
# местах. И обе означают, что дальше идти незачем: домен не указывает сюда — сертификат не
# выпустится; порт занят — узел не поднимется.
#
# Раньше здесь было предупреждение. Предупреждение в скрипте, который после него доходит до
# конца и печатает код, — это не предупреждение, а строка, которую пролистывают.
if [ "$SKIP_CHECKS" = "0" ]; then
	say "проверки"

	mine="$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || echo '')"
	resolved="$(dig +short A "$DOMAIN" 2>/dev/null | tail -n1 || echo '')"
	if [ -z "$mine" ] || [ -z "$resolved" ]; then
		rm -f "$TMP_CONFIG"
		die "не вышло сверить $DOMAIN с адресом сервера — проверь сеть либо запусти с --skip-checks"
	fi
	if [ "$mine" != "$resolved" ]; then
		rm -f "$TMP_CONFIG"
		cat >&2 <<EOF

ошибка: $DOMAIN указывает на $resolved, а этот сервер — $mine

Сертификат на такой домен не выпустится: проверка Let's Encrypt придёт не сюда. Поправь запись
A и запусти скрипт заново.

Узел за NAT — единственный случай, когда это нормально: снаружи он виден по одному адресу, а
сам себя знает по другому. Тогда --skip-checks.
EOF
		exit 1
	fi
	echo "домен $DOMAIN указывает сюда ($mine)"

	for port in 80 443; do
		if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$port\$"; then
			holder="$(ss -lntp 2>/dev/null | grep -E "[:.]$port\b" | head -n1 || true)"
			rm -f "$TMP_CONFIG"
			printf '\nошибка: порт %s занят — узел не поднимется\n' "$port" >&2
			[ -n "$holder" ] && printf '  %s\n' "$holder" >&2
			printf '\nОсвободи порт либо запусти с --skip-checks, если знаешь, что делаешь.\n' >&2
			exit 1
		fi
		echo "порт $port свободен"
	done
fi

# Проверки прошли — настройки становятся настоящими.
install -m 0640 -o root -g qdiver "$TMP_CONFIG" "$CONFIG"
rm -f "$TMP_CONFIG"
rollback_add config

if [ -n "$EMAIL" ]; then
	sed -i "s|^acme_email = .*|acme_email = \"$EMAIL\"|" "$CONFIG"
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

rollback_add service
systemctl daemon-reload
systemctl enable --now qd-node >/dev/null

sleep 2
systemctl is-active --quiet qd-node || {
	echo "служба не поднялась:" >&2
	journalctl -u qd-node -n 20 --no-pager >&2 || true
	die "узел не запустился"
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
