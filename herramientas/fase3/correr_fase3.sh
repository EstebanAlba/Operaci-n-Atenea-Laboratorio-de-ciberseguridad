#!/bin/sh
# Ejecuta la fase 3 completa dentro del contenedor auditor:
#   docker compose exec auditor sh /herramientas/fase3/correr_fase3.sh
# Resultados en evidencias/fase3/
set -e
BASE=/herramientas/fase3
OUT=/evidencias/fase3
mkdir -p "$OUT"
cd "$BASE/datos"

echo "1. Hash de los registros ANTES de analizarlos (preservacion)"
sha256sum *.csv > "$OUT/hashes_registros.txt"
cat "$OUT/hashes_registros.txt"

echo; echo "2. Analisis de cada caso"
for f in *.csv; do
  caso="${f%.csv}"
  mkdir -p "$OUT/$caso"
  python3 "$BASE/analizador.py" "$f" "$OUT/$caso" > "$OUT/$caso/reporte.txt"
  echo "   $caso: $(tail -2 "$OUT/$caso/reporte.txt" | head -1)"
done

echo; echo "3. Pruebas automaticas"
python3 "$BASE/pruebas.py" | tee "$OUT/pruebas.txt"

echo; echo "4. Los registros no cambiaron durante el analisis"
sha256sum -c "$OUT/hashes_registros.txt"

cd "$OUT" && find . -type f ! -name hashes_resultados.txt | sort | xargs sha256sum > hashes_resultados.txt
echo; echo "Listo. Resultados y hashes en evidencias/fase3/"
