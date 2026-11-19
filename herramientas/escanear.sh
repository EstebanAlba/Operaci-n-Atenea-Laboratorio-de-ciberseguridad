#!/bin/sh
# Escaneos autorizados de la fase 2. Se ejecuta DENTRO del contenedor auditor:
#   docker compose exec auditor sh /herramientas/escanear.sh
#   docker compose exec auditor sh /herramientas/escanear.sh --con-autenticacion   (paso 5, solo si el alcance lo autoriza)
#   docker compose exec -e ETAPA=despues auditor sh /herramientas/escanear.sh --con-autenticacion   (tras el plan de cierre)
# Objetivos permitidos: 192.168.56.10 (PORTAL-01) y 192.168.56.11 (REPO-01). Nada fuera de 192.168.56.0/24.
set -e
OUT=/evidencias/${ETAPA:-antes}     # ETAPA=antes (por defecto) o ETAPA=despues
mkdir -p "$OUT"
OBJ="192.168.56.10 192.168.56.11"
cd "$OUT"

echo "Inicio: $(date -Iseconds)  Auditor: $(hostname -i)" > 00_bitacora.txt

echo "[1/4] Descubrimiento de equipos"
nmap -sn 192.168.56.0/24 -oN 01_descubrimiento.txt -oX 01_descubrimiento.xml >/dev/null

echo "[2/4] Servicios y versiones en 22, 80 y 443 (comando del enunciado)"
nmap -sT -sV -p 22,80,443 $OBJ -oN 02_servicios.txt -oX 02_servicios.xml >/dev/null

echo "[3/4] Todos los puertos TCP (para descartar servicios no declarados)"
nmap -sT -p- --min-rate 500 $OBJ -oN 03_todos_los_puertos.txt -oX 03_todos_los_puertos.xml >/dev/null

echo "[4/4] Scripts de categoria safe sobre los puertos abiertos"
nmap -sT -sV -p 22,80 --script "http-title,http-headers,http-methods,ssh-hostkey,ssh2-enum-algos" $OBJ \
     -oN 04_detalle_servicios.txt -oX 04_detalle_servicios.xml >/dev/null

if [ "$1" = "--con-autenticacion" ]; then
  echo "[5] Metodos de autenticacion SSH (script intrusivo, autorizado en el alcance)"
  nmap -sT -p 22 --script ssh-auth-methods 192.168.56.11 -oN 05_ssh_autenticacion.txt -oX 05_ssh_autenticacion.xml >/dev/null
fi

echo "Fin: $(date -Iseconds)" >> 00_bitacora.txt
sha256sum 0* > hashes_sha256.txt
echo "Listo. Evidencias y hashes en evidencias/${ETAPA:-antes}/"
