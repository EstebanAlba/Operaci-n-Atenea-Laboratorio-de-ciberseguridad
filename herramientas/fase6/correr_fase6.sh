#!/bin/sh
# Ejecuta la fase 6 completa dentro del contenedor auditor:
#   docker compose exec auditor sh /herramientas/fase6/correr_fase6.sh
# Resultados en evidencias/fase6/
set -e
BASE=/herramientas/fase6
OUT=/evidencias/fase6
mkdir -p "$OUT"

echo "1. Generacion de los registros simulados (semilla fija) y hash antes del analisis"
python3 "$BASE/generar_registros.py" "$OUT/registros"
(cd "$OUT/registros" && sha256sum *.csv) | tee "$OUT/hashes_registros.txt"

echo; echo "2. Deteccion y evaluacion por escenario"
python3 "$BASE/detector.py" "$OUT/registros/registros_simulados.csv" "$OUT/registros/escenarios.csv" "$OUT" \
  | tee "$OUT/reporte_deteccion.txt"

echo; echo "3. Calibracion de la regla de descargas (reto)"
python3 "$BASE/calibracion.py" "$OUT/registros/registros_simulados.csv" "$OUT/registros/escenarios.csv" \
  | tee "$OUT/calibracion.txt"

echo; echo "4. Pruebas automaticas"
python3 "$BASE/pruebas.py" | tee "$OUT/pruebas.txt"

echo; echo "5. Los registros no cambiaron durante el analisis"
(cd "$OUT/registros" && sha256sum -c "$OUT/hashes_registros.txt")

cd "$OUT" && find . -type f ! -name hashes_fase6.txt | sort | xargs sha256sum > hashes_fase6.txt
echo; echo "Listo. Resultados y hashes en evidencias/fase6/"
