#!/bin/sh
# Ejecuta la fase 7 completa dentro del contenedor auditor:
#   docker compose exec auditor sh /herramientas/fase7/correr_fase7.sh
# Requiere que las evidencias de las fases 2 a 6 esten en evidencias/. Resultados en evidencias/fase7/
set -e
BASE=/herramientas/fase7
OUT=/evidencias/fase7
mkdir -p "$OUT"

echo "1. Hash de las matrices antes de verificarlas"
(cd "$BASE" && sha256sum matriz_cumplimiento.csv raci.csv datos/*) | tee "$OUT/hashes_entradas.txt"

echo; echo "2. Verificacion de la matriz de cumplimiento contra las evidencias y de la matriz RACI"
python3 "$BASE/verificar_cumplimiento.py" "$BASE/matriz_cumplimiento.csv" "$BASE/raci.csv" "$OUT" \
  | tee "$OUT/reporte_cumplimiento.txt"

echo; echo "3. Reto: solicitud de acceso a todos los datos y solicitud justificada"
{
  python3 "$BASE/solicitud_acceso.py" "$BASE/datos/solicitud_acceso_total.json"
  echo
  python3 "$BASE/solicitud_acceso.py" "$BASE/datos/solicitud_justificada.json"
} | tee "$OUT/solicitudes.txt"

echo; echo "4. Pruebas automaticas"
python3 "$BASE/pruebas.py" | tee "$OUT/pruebas.txt"

cd "$OUT" && find . -type f ! -name hashes_fase7.txt | sort | xargs sha256sum > hashes_fase7.txt
echo; echo "Listo. Resultados y hashes en evidencias/fase7/"
