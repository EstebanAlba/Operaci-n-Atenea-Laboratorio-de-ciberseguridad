#!/bin/sh
# Ejecuta la fase 5 completa dentro del contenedor auditor:
#   docker compose exec auditor sh /herramientas/fase5/correr_fase5.sh
# Resultados en evidencias/fase5/
set -e
BASE=/herramientas/fase5
OUT=/evidencias/fase5
mkdir -p "$OUT"

echo "1. Hash de los datos de entrada ANTES de usarlos"
(cd "$BASE/datos" && sha256sum *) | tee "$OUT/hashes_entradas.txt"

echo; echo "2. Cifrado, hash, firma, certificados, claves (evidencias 01 a 07)"
python3 "$BASE/fase5.py" demo --salida "$OUT" --evidencias /evidencias > "$OUT/reporte_fase5.txt"
grep -E "^(0[1-7] - |  [A-E]\. |  Certificado|  Emitido)" "$OUT/reporte_fase5.txt"

echo; echo "3. Pruebas automaticas"
python3 "$BASE/pruebas.py" | tee "$OUT/pruebas.txt"

echo; echo "4. Verificacion independiente del paquete firmado (solo con material publico)"
HUELLA=$(cat "$OUT/ca_huella_sha256.txt")
{
  echo "--- Paquete original ---"
  python3 "$BASE/fase5.py" verificar "$OUT/paquete_firmado" --esperado director01@atenea.test --huella-ca "$HUELLA"
} > "$OUT/verificacion_independiente.txt" 2>&1 || { cat "$OUT/verificacion_independiente.txt"; echo "ERROR: el paquete legitimo debia aceptarse"; exit 1; }
rm -rf /tmp/paquete_alterado && cp -r "$OUT/paquete_firmado" /tmp/paquete_alterado
sed -i 's/0\.82/0.92/' /tmp/paquete_alterado/informe_P01.txt
{
  echo; echo "--- Mismo paquete tras cambiar un caracter del informe ---"
  if python3 "$BASE/fase5.py" verificar /tmp/paquete_alterado --esperado director01@atenea.test --huella-ca "$HUELLA"; then
    echo "ERROR: el paquete alterado debia rechazarse"; exit 1
  fi
} >> "$OUT/verificacion_independiente.txt" 2>&1
cat "$OUT/verificacion_independiente.txt"

echo; echo "5. Hash de todas las evidencias de la fase 5"
cd "$OUT" && find . -type f ! -name hashes_fase5.txt | sort | xargs sha256sum > hashes_fase5.txt
echo "Listo. Resultados y hashes en evidencias/fase5/"
