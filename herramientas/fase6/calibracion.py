"""Barrido de calibracion de la regla D1: cuantas alertas falsas y cuantos incidentes detecta segun el multiplicador k
de la linea base y segun se use o no el calendario de entregas. Uso: python3 calibracion.py registros.csv escenarios.csv"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import detector as det  # noqa: E402

eventos = det.leer(sys.argv[1])
escenarios = det.leer_escenarios(sys.argv[2])
incidentes_descarga = {"S3", "S4"}


def medir(alertas):
    for a in alertas:
        s = det.asignar(a, escenarios)
        a["escenario"] = s["id"] if s else ""
    tipo = {s["id"]: s["tipo"] for s in escenarios}
    falsas = sum(1 for a in alertas if tipo.get(a["escenario"]) != "incidente")
    detectados = sorted({a["escenario"] for a in alertas if a["escenario"] in incidentes_descarga})
    return len(alertas), falsas, detectados


d0, _ = det.reglas_descargas(eventos)
n, f, inc = medir(d0)
print(f"{'Configuracion':<44}{'Alertas':>8}{'Falsas':>8}  Incidentes de descarga detectados (de S3 y S4)")
print(f"{'Umbral fijo de 500 MB (D0)':<44}{n:>8}{f:>8}  {', '.join(inc) or 'ninguno'}")
for k in (2, 3, 4, 5, 6, 8):
    for cal in (True, False):
        _, d1 = det.reglas_descargas(eventos, k=k, usar_calendario=cal)
        n, f, inc = medir(d1)
        nombre = f"Linea base, k = {k}, {'con' if cal else 'sin'} calendario de entregas"
        print(f"{nombre:<44}{n:>8}{f:>8}  {', '.join(inc) or 'ninguno'}")
