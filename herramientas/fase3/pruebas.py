"""Verifica que el analizador produzca los resultados esperados en cada caso de prueba.
Uso: python3 pruebas.py   (desde cualquier carpeta)"""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from analizador import analizar  # noqa: E402

DATOS = Path(__file__).parent / "datos"
# caso: (alertas esperadas como (regla, confianza), filas descartadas esperadas, que demuestra)
ESPERADO = {
    "muestra_enunciado.csv": ([("R3", "Alta"), ("R2", "Media")], 0,
                              "La muestra del enunciado activa R2 y R3; R1 no, porque solo hay 2 fallos"),
    "caso_normal.csv": ([], 0, "La actividad normal no genera alertas"),
    "caso_ataque.csv": ([("R1", "Alta"), ("R3", "Alta"), ("R2", "Alta"), ("R2", "Alta")], 0,
                        "Una toma de cuenta activa las tres reglas con confianza alta"),
    "caso_falso_positivo.csv": ([("R2", "Baja")] * 4 + [("R3", "Baja")], 0,
                                "Las alertas de un uso habitual o aprobado quedan en confianza baja"),
    "caso_incompleto.csv": ([("R2", "Baja")], 4,
                            "Las filas malas se descartan sin detener el analisis"),
}

fallas = 0
for caso, (alertas_esp, descartes_esp, idea) in ESPERADO.items():
    _, descartes, alertas = analizar(DATOS / caso)
    obtenido = Counter((a["regla"], a["confianza"]) for a in alertas)
    ok = obtenido == Counter(alertas_esp) and len(descartes) == descartes_esp
    fallas += not ok
    print(f"[{'OK' if ok else 'FALLA'}] {caso}: {len(alertas)} alertas, {len(descartes)} descartadas. {idea}")
    if not ok:
        print(f"        esperado {sorted(alertas_esp)} / {descartes_esp} descartes; obtenido {sorted(obtenido.elements())}")
print(f"\n{len(ESPERADO) - fallas} de {len(ESPERADO)} pruebas correctas")
sys.exit(1 if fallas else 0)
