#!/bin/bash
# Descarga e instala el Panel SSH. Uso: bash <(curl -fsSL https://raw.githubusercontent.com/redenazi28-lang/Tienda/panel-ssh/instalar.sh)
set -e
[ "$(id -u)" = "0" ] || { echo "Ejecutalo como root."; exit 1; }
U=https://raw.githubusercontent.com/redenazi28-lang/Tienda/panel-ssh
D=/root/panelvpn
mkdir -p "$D"
echo "==> Descargando el panel"
for f in panel.py index.html install.sh ws.py LEEME.txt; do
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$U/$f" -o "$D/$f"
  else wget -q -O "$D/$f" "$U/$f"; fi
done
rm -rf /root/pp /root/panelvpn.b64 /root/panelvpn.tgz 2>/dev/null || true
bash "$D/install.sh"
