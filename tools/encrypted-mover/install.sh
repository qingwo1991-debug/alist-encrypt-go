#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi
: "${NODE_ID:?NODE_ID is required}"
: "${PARITY:?PARITY odd or even is required}"
ARIA2_SECRET=${ARIA2_SECRET:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')}
OPENLIST_PASSWORD=${OPENLIST_PASSWORD:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')}
: "${ENCRYPTION_KEY_FILE:?ENCRYPTION_KEY_FILE is required}"
case "$PARITY" in odd|even) ;; *) echo "invalid PARITY" >&2; exit 1;; esac
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y aria2 ca-certificates curl python3
id encrypted-mover >/dev/null 2>&1 || useradd --system --home /var/lib/encrypted-mover --shell /usr/sbin/nologin encrypted-mover
install -d -o encrypted-mover -g encrypted-mover -m 0700 /var/lib/encrypted-mover/work /var/log/encrypted-mover /var/lib/openlist /var/lib/openlist/temp /var/lib/openlist/log
install -d -o root -g encrypted-mover -m 0750 /etc/encrypted-mover
install -d -o root -g root -m 0755 /opt/encrypted-mover /opt/openlist
install -o root -g root -m 0755 "$SCRIPT_DIR/encrypted_mover.py" /opt/encrypted-mover/encrypted_mover.py
install -o root -g root -m 0755 "$SCRIPT_DIR/encrypted-mover" /usr/local/bin/encrypted-mover
install -o root -g root -m 0755 "$SCRIPT_DIR/encrypt-tool-linux-amd64" /usr/local/bin/encrypt-tool
install -o root -g root -m 0755 "$SCRIPT_DIR/openlist" /opt/openlist/openlist
JWT_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
sed "s/JWT_SECRET/$JWT_SECRET/g" "$SCRIPT_DIR/openlist-config.example.json" > /var/lib/openlist/config.json
chown encrypted-mover:encrypted-mover /var/lib/openlist/config.json
chmod 0600 /var/lib/openlist/config.json
sed -e "s/NODE_ID/$NODE_ID/g" -e "s/PARITY/$PARITY/g" -e "s/ARIA2_SECRET/$ARIA2_SECRET/g" "$SCRIPT_DIR/config.example.json" > /etc/encrypted-mover/config.json
sed -e "s/ARIA2_SECRET/$ARIA2_SECRET/g" -e "s/BT_PORT/${BT_PORT:-51413}/g" "$SCRIPT_DIR/aria2.conf" > /etc/encrypted-mover/aria2.conf
chown encrypted-mover:encrypted-mover /etc/encrypted-mover/config.json /etc/encrypted-mover/aria2.conf
chmod 0600 /etc/encrypted-mover/config.json /etc/encrypted-mover/aria2.conf
install -o encrypted-mover -g encrypted-mover -m 0600 /dev/null /etc/encrypted-mover/openlist-password
printf '%s' "$OPENLIST_PASSWORD" > /etc/encrypted-mover/openlist-password
install -o encrypted-mover -g encrypted-mover -m 0600 "$ENCRYPTION_KEY_FILE" /etc/encrypted-mover/encryption-key
install -o root -g root -m 0644 "$SCRIPT_DIR/openlist.service" /etc/systemd/system/openlist.service
install -o root -g root -m 0644 "$SCRIPT_DIR/aria2.service" /etc/systemd/system/aria2.service
install -o root -g root -m 0644 "$SCRIPT_DIR/encrypted-mover.service" /etc/systemd/system/encrypted-mover.service
touch /var/lib/encrypted-mover/aria2.session
chown -R encrypted-mover:encrypted-mover /var/lib/encrypted-mover /var/log/encrypted-mover /var/lib/openlist
systemctl daemon-reload
systemctl enable openlist aria2 encrypted-mover
systemctl start openlist
for i in $(seq 1 60); do curl -fsS http://127.0.0.1:5244/ping >/dev/null && break; sleep 1; done
systemctl stop openlist
runuser -u encrypted-mover -- /opt/openlist/openlist admin set "$OPENLIST_PASSWORD" --data /var/lib/openlist >/dev/null
systemctl start openlist aria2
echo "base services installed; provision storage, then start encrypted-mover"
