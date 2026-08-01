#!/usr/bin/env bash
# Черновик установщика узла. Ставит пользователя, каталоги, конфиг и юнит.
#
# Пока разворачивает уже залитый бинарь; выкачивание релиза с проверкой подписи придёт
# вместе с решением 002 (§3.1).
set -euo pipefail

usage() {
	cat >&2 <<'EOF'
setup-node.sh --id <идентификатор> --domain <имя> [--genesis <отпечаток>] [--peers a:443,b:443]
EOF
	exit 2
}

ID=""
DOMAIN=""
GENESIS=""
PEERS=""

while [ $# -gt 0 ]; do
	case "$1" in
	--id) ID="$2"; shift 2 ;;
	--domain) DOMAIN="$2"; shift 2 ;;
	--genesis) GENESIS="$2"; shift 2 ;;
	--peers) PEERS="$2"; shift 2 ;;
	*) usage ;;
	esac
done

[ -n "$ID" ] && [ -n "$DOMAIN" ] || usage
[ -x /usr/local/bin/qd-node ] || { echo "нет /usr/local/bin/qd-node" >&2; exit 1; }

id -u qdiver >/dev/null 2>&1 || useradd --system --home-dir /var/lib/qdiver --shell /usr/sbin/nologin qdiver
install -d -o qdiver -g qdiver -m 0700 /var/lib/qdiver /var/lib/qdiver/certs
install -d -m 0755 /etc/qdiver

# Списком в TOML: qdiver1:443 → ["qdiver1:443"]
peers_toml="[]"
if [ -n "$PEERS" ]; then
	peers_toml="[$(echo "$PEERS" | sed 's/[^,]*/"&"/g')]"
fi

cat > /etc/qdiver/node.toml <<EOF
id     = "$ID"
domain = "$DOMAIN"

listen      = ":443"
listen_tcp  = ":443"
listen_acme = ":80"

key_file = "/var/lib/qdiver/node.key"
data_dir = "/var/lib/qdiver"

genesis = "$GENESIS"
peers   = $peers_toml

acme_email = ""
log_level  = "info"
EOF
chown root:qdiver /etc/qdiver/node.toml
chmod 0640 /etc/qdiver/node.toml

# QUIC упирается в приёмный буфер ядра куда раньше, чем в канал.
cat > /etc/sysctl.d/99-qdiver.conf <<'EOF'
net.core.rmem_max = 7500000
net.core.wmem_max = 7500000
EOF
sysctl -q -p /etc/sysctl.d/99-qdiver.conf

systemctl daemon-reload
systemctl enable qd-node >/dev/null

echo "узел $ID настроен"
echo "публичный ключ:"
sudo -u qdiver /usr/local/bin/qd-node -config /etc/qdiver/node.toml -show-key
