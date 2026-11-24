"""Pruebas automaticas de la fase 7. Uso: python3 pruebas.py"""
import copy
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).parent
sys.path.insert(0, str(BASE))
import solicitud_acceso as sa  # noqa: E402
import verificar_cumplimiento as vc  # noqa: E402

RAIZ = vc.raiz_por_defecto()
MATRIZ = vc.leer_csv(BASE / "matriz_cumplimiento.csv")
RACI = vc.leer_csv(BASE / "raci.csv")
ROLES, HALLAZGOS = vc.evaluar_raci(RACI)
RESULTADO = vc.evaluar_matriz(MATRIZ, RAIZ, set(ROLES))
CATALOGO = sa.cargar_catalogo()


def fila(id_):
    return copy.deepcopy(next(f for f in MATRIZ if f["id"] == id_))


def raci_con(proceso, rol, valor):
    filas = copy.deepcopy(RACI)
    for f in filas:
        if f["proceso"] == proceso:
            f[rol] = valor
    return vc.evaluar_raci(filas)[1]


def evidencia_alterada():
    """Copia la evidencia de la fase 4 a una carpeta temporal, cambia un caracter y la verifica."""
    tmp = Path(tempfile.mkdtemp())
    shutil.copytree(RAIZ / "evidencias" / "fase4", tmp / "evidencias" / "fase4")
    demo = tmp / "evidencias" / "fase4" / "demo.txt"
    demo.write_text(demo.read_text(encoding="utf-8").replace("403", "200", 1), encoding="utf-8")
    r = vc.evaluar_matriz([fila("C02")], tmp, set(ROLES))[0]
    return r["verificacion"] == "INCONSISTENTE" and "ALTERADA" in r["checks"][0]["integridad"]


def solicitud(nombre):
    return sa.decidir(json.loads((BASE / "datos" / nombre).read_text(encoding="utf-8")), CATALOGO)


TOTAL = {d["recurso"]: d for d in solicitud("solicitud_acceso_total.json")}
JUST = {d["recurso"]: d for d in solicitud("solicitud_justificada.json")}
controles = {c.strip() for f in MATRIZ for c in f["control_iso"].split(",") if re.match(r"A\.\d+\.\d+", c.strip())}

casos = [
    ("La matriz vigente no tiene inconsistencias",
     all(f["verificacion"] == "consistente" for f in RESULTADO)),
    ("Todas las evidencias citadas existen y su hash coincide con el manifiesto de su fase",
     all(c["integridad"] == "hash verificado" for f in RESULTADO for c in f["checks"])),
    ("Cada obligacion parcial o en brecha tiene accion, responsable y plazo",
     all(f["accion"] and f["responsable"] and f["plazo_dias"] for f in MATRIZ if f["estado"] != "cumple")),
    (f"La matriz relaciona al menos seis controles de ISO/IEC 27001 (tiene {len(controles)})", len(controles) >= 6),
    ("La matriz distingue dato personal, dato sensible y propiedad intelectual",
     {"dato personal", "dato sensible", "propiedad intelectual"} <= {f["informacion"] for f in MATRIZ}),
    ("Una evidencia alterada en un caracter se detecta y la obligacion queda inconsistente", evidencia_alterada()),
    ("Declarar 'cumple' con una evidencia inexistente se marca como inconsistente",
     vc.evaluar_matriz([{**fila("C01"), "evidencia": "evidencias/fase4/no_existe.txt"}], RAIZ, set(ROLES))[0]
     ["verificacion"] == "INCONSISTENTE"),
    ("La evidencia del escaneo inicial no sirve para C14: el SSH aun aceptaba contrasena",
     vc.evaluar_matriz([{**fila("C14"), "evidencia": "evidencias/antes/05_ssh_autenticacion.txt",
                         "debe_contener": "publickey", "no_debe_contener": "password"}], RAIZ, set(ROLES))[0]
     ["verificacion"] == "INCONSISTENTE"),
    ("Un responsable que no existe en la matriz RACI se marca como inconsistente",
     vc.evaluar_matriz([{**fila("C07"), "responsable": "Alguien"}], RAIZ, set(ROLES))[0]["verificacion"]
     == "INCONSISTENTE"),
    ("La matriz RACI vigente cumple las reglas de COBIT 5 definidas", not HALLAZGOS),
    ("RACI: dos responsables finales (A) en un proceso se detecta", bool(raci_con("DSS05", "Coordinador de TI", "A"))),
    ("RACI: TI supervisando su propio control interno (MEA02) se detecta",
     bool(raci_con("MEA02", "Coordinador de TI", "R"))),
    ("RACI: auditoria ejecutando un proceso de gestion (DSS05) pierde independencia",
     bool(raci_con("DSS05", "Auditoria interna", "R"))),
    ("Reto: 'acceso a todo' no concede ningun recurso de otro proyecto",
     not any(d["decision"].startswith("CONCEDER") for d in TOTAL.values())),
    ("Reto: los recursos del propio proyecto siguen como estaban y la tabla de correspondencia se niega",
     all(TOTAL[r]["decision"] == "YA AUTORIZADO" for r in TOTAL if r.startswith("P01/"))
     and TOTAL["DATA-01/tabla_correspondencia.csv"]["decision"] == "DENEGAR"),
    ("Reto: con motivo y aprobacion del director dueno se concede la version agregada, en lectura y por 90 dias",
     JUST["P02/muestra_P02.csv"]["decision"] == "CONCEDER CON CONDICIONES"
     and any("agregada" in c for c in JUST["P02/muestra_P02.csv"]["condiciones"])
     and any("90 dias" in c for c in JUST["P02/muestra_P02.csv"]["condiciones"])),
    ("Reto: con motivo pero sin aprobacion queda pendiente",
     JUST["P02/modelo_P02.bin"]["decision"] == "PENDIENTE"),
    ("Reto: la aprobacion de un director de otro proyecto no vale",
     sa.decidir({**json.loads((BASE / "datos" / "solicitud_justificada.json").read_text(encoding="utf-8")),
                 "aprobaciones": ["director01:P02/muestra_P02.csv"]}, CATALOGO)[0]["decision"] == "PENDIENTE"),
]

ok = 0
for nombre, resultado in casos:
    print(f"[{'OK' if resultado else 'FALLA'}] {nombre}")
    ok += bool(resultado)
print(f"\n{ok} de {len(casos)} pruebas correctas")
sys.exit(0 if ok == len(casos) else 1)
