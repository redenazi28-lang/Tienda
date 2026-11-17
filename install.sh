#!/bin/bash
# Instalador del Panel SSH. Uso: sudo bash install.sh
set -e
[ "$(id -u)" = "0" ] || { echo "Ejecutalo como root: sudo bash install.sh"; exit 1; }
cd "$(dirname "$0")"
[ -f panel.py ] && [ -f index.html ] || { echo "Faltan panel.py o index.html al lado de install.sh"; exit 1; }

APP=/opt/panelvpn
DATA=/var/lib/panelvpn
PORT="${PANEL_PORT:-8443}"

echo "==> Instalando programas necesarios"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || true
  apt-get install -y -qq python3 openssl openssh-client sshpass procps >/dev/null || echo "   (aviso: no pude instalar algún paquete; sigo)"
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q python3 openssl openssh-clients sshpass procps-ng || echo "   (aviso: no pude instalar algún paquete; sigo)"
fi
command -v python3 >/dev/null 2>&1 || { echo "Falta python3 y no pude instalarlo."; exit 1; }

echo "==> Copiando el panel a $APP"
mkdir -p "$APP" "$DATA"
chmod 700 "$DATA"
cp panel.py index.html "$APP/"
chmod 755 "$APP/panel.py"

[ -f "$DATA/id_ed25519" ] || ssh-keygen -q -t ed25519 -N "" -C panelvpn -f "$DATA/id_ed25519"
if [ ! -f "$DATA/cert.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=panelvpn" \
    -keyout "$DATA/key.pem" -out "$DATA/cert.pem" >/dev/null 2>&1
  chmod 600 "$DATA/key.pem"
fi

PASS="$(python3 -c 'import secrets;print(secrets.token_urlsafe(9))')"
NEW=1
echo "$PASS" | PANEL_DATA="$DATA" python3 "$APP/panel.py" --init-admin || NEW=0

cat > /etc/systemd/system/panelvpn.service <<EOF
[Unit]
Description=Panel SSH
After=network.target

[Service]
Environment=PANEL_DIR=$APP
Environment=PANEL_DATA=$DATA
Environment=PANEL_PORT=$PORT
ExecStart=/usr/bin/env python3 $APP/panel.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable -q panelvpn
systemctl restart panelvpn

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then ufw allow "$PORT"/tcp >/dev/null || true; fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "======================================================"
echo " Panel SSH instalado"
echo " Direccion:  https://${IP:-IP-DE-TU-VPS}:$PORT"
if [ "$NEW" = "1" ]; then
  echo " Usuario:    admin"
  echo " Contrasena: $PASS"
  echo " Anotala ahora y cambiala desde Mas > Tu cuenta."
else
  echo " Ya habia un administrador: tu usuario y contrasena no cambiaron."
fi
echo
echo " El navegador va a avisar que el certificado no es de"
echo " confianza (es propio del panel). Toca Avanzado > Continuar."
echo " Si tu proveedor tiene firewall, abri el puerto $PORT."
echo "======================================================"
