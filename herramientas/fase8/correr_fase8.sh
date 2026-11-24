#!/bin/sh
# Ejecuta la fase 8 dentro del contenedor auditor:
#   docker compose exec auditor sh /herramientas/fase8/correr_fase8.sh
# Requiere haber ejecutado antes las fases 2 a 7. Resultados en evidencias/fase8/
set -e
BASE=/herramientas/fase8
OUT=/evidencias/fase8
mkdir -p "$OUT"

echo "1. Hash del plan, el presupuesto y los indicadores"
(cd "$BASE" && sha256sum plan.csv presupuesto.csv indicadores.csv) | tee "$OUT/hashes_entradas.txt"

echo; echo "2. Plan de 90 dias, presupuesto, linea base de indicadores y reto"
python3 "$BASE/integrar.py" "$OUT" | tee "$OUT/reporte_integracion.txt"

echo; echo "3. Pruebas automaticas"
python3 "$BASE/pruebas.py" | tee "$OUT/pruebas.txt"

echo; echo "4. Verificacion final de las pruebas de todas las fases"
for f in /evidencias/fase3/pruebas.txt /evidencias/fase4/pruebas_pytest.txt /evidencias/fase5/pruebas.txt \
         /evidencias/fase6/pruebas.txt /evidencias/fase7/pruebas.txt "$OUT/pruebas.txt"; do
  printf "  %-38s %s\n" "${f#/evidencias/}" "$(grep -E 'pruebas correctas|passed' "$f" | tail -1 | sed 's/=//g; s/^ *//')"
done | tee "$OUT/resumen_pruebas.txt"

cd "$OUT" && find . -type f ! -name hashes_fase8.txt | sort | xargs sha256sum > hashes_fase8.txt
echo; echo "Listo. Resultados y hashes en evidencias/fase8/"
