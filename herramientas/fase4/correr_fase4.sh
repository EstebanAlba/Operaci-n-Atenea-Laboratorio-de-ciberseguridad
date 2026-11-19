#!/bin/sh
# Ejecuta la demostracion de la fase 4 desde el auditor:
#   docker compose exec auditor sh /herramientas/fase4/correr_fase4.sh
set -e
OUT=/evidencias/fase4
mkdir -p "$OUT"
echo "1. Demostracion contra el portal en vivo"
python3 /herramientas/fase4/demo.py http://192.168.56.10 | tee "$OUT/demo.txt"

echo; echo "2. Busqueda de secretos en el registro del portal"
if grep -E "Investiga-0|Admin-01!|Externo-0|Director-0|Estudiante-0|JBSWY3DPEHPK3PXP" "$OUT/accesos.csv"; then
  echo "SE ENCONTRARON SECRETOS EN EL REGISTRO" | tee "$OUT/busqueda_secretos.txt"
else
  echo "Ninguna contrasena ni secreto MFA en accesos.csv" | tee "$OUT/busqueda_secretos.txt"
fi

echo; echo "3. Analizador de la fase 3 sobre el registro del portal"
python3 /herramientas/fase3/analizador.py "$OUT/accesos.csv" "$OUT/analisis_registro" | tee "$OUT/analisis_registro.txt" | tail -4

cd "$OUT" && find . -type f ! -name hashes_fase4.txt | sort | xargs sha256sum > hashes_fase4.txt
echo; echo "Listo. Evidencias y hashes en evidencias/fase4/"
