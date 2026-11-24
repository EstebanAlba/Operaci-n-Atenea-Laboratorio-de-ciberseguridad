"""Verificacion de la matriz de cumplimiento y de la matriz RACI - Operacion Atenea, fase 7.

La matriz de cumplimiento relaciona cada obligacion con su evidencia en el repositorio. Este script no
decide si el centro cumple la ley: comprueba que lo que la matriz afirma esta respaldado por evidencias
reales e integras, y que la matriz RACI respeta la separacion entre gobierno, gestion y supervision.

Para cada evidencia citada verifica:
  1. que el archivo existe;
  2. que su SHA-256 coincide con el manifiesto de hashes de su fase (evidencias/*/hashes*.txt);
  3. que contiene el texto que demuestra el resultado (columna debe_contener) y no contiene el que
     demostraria lo contrario (columna no_debe_contener). Con varias evidencias separadas por ";",
     los patrones se separan igual y se aplican en el mismo orden.
Luego contrasta el estado declarado (cumple, parcial, brecha) con lo verificado.

Uso:  python3 verificar_cumplimiento.py [matriz.csv] [raci.csv] [carpeta_salida]
"""
import csv
import hashlib
import os
import sys
from pathlib import Path

BASE = Path(__file__).parent
ESTADOS = {"cumple", "parcial", "brecha"}
ROLES_OPERACION = {"Coordinador de TI"}          # quienes operan los sistemas
ROL_GOBIERNO = "Direccion del CAI"
ROL_AUDITORIA = "Auditoria interna"


def raiz_por_defecto():
    """Dentro del contenedor auditor las carpetas estan montadas en /evidencias y /herramientas."""
    if os.environ.get("RAIZ"):
        return Path(os.environ["RAIZ"])
    return Path("/") if Path("/evidencias").is_dir() else BASE.parents[1]


def sha256(ruta):
    return hashlib.sha256(Path(ruta).read_bytes()).hexdigest()


# ---------------------------------------------------------------- manifiestos de hashes
def cargar_manifiestos(raiz):
    """Devuelve {ruta absoluta: hash esperado} a partir de todos los hashes*.txt de evidencias/."""
    esperado = {}
    for manifiesto in sorted((raiz / "evidencias").rglob("hashes*.txt")):
        for linea in manifiesto.read_text(encoding="utf-8").splitlines():
            partes = linea.split(maxsplit=1)
            if len(partes) != 2 or len(partes[0]) != 64:
                continue
            ruta = (manifiesto.parent / partes[1].strip()).resolve()
            if ruta.exists():                     # entradas relativas a otra carpeta se ignoran
                esperado[ruta] = partes[0]
    return esperado


def verificar_evidencia(raiz, ruta_rel, manifiestos, debe="", no_debe=""):
    ruta = (raiz / ruta_rel).resolve()
    r = {"ruta": ruta_rel, "existe": ruta.is_file(), "integridad": "", "contenido": "", "ok": False}
    if not r["existe"]:
        r["integridad"] = "no existe"
        return r
    esperado = manifiestos.get(ruta)
    if esperado is None:
        r["integridad"] = "sin manifiesto"
    elif esperado == sha256(ruta):
        r["integridad"] = "hash verificado"
    else:
        r["integridad"] = "ALTERADA (el hash no coincide con el manifiesto)"
    texto = ruta.read_text(encoding="utf-8", errors="replace")
    faltan = [debe] if debe and debe not in texto else []
    sobran = [no_debe] if no_debe and no_debe in texto else []
    if faltan:
        r["contenido"] = f"no contiene '{debe}'"
    elif sobran:
        r["contenido"] = f"contiene '{no_debe}'"
    else:
        r["contenido"] = "resultado presente" if debe or no_debe else "sin patron"
    r["ok"] = r["integridad"] == "hash verificado" and not faltan and not sobran
    return r


# ---------------------------------------------------------------- matriz de cumplimiento
def leer_csv(ruta):
    with open(ruta, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def evaluar_matriz(filas, raiz, roles_validos):
    manifiestos = cargar_manifiestos(raiz)
    resultado = []
    for f in filas:
        problemas = []
        estado = f["estado"].strip().lower()
        if estado not in ESTADOS:
            problemas.append(f"estado desconocido '{f['estado']}'")
        evidencias = [e.strip() for e in f["evidencia"].split(";") if e.strip()]
        debe = [x.strip() for x in f["debe_contener"].split(";")]
        no_debe = [x.strip() for x in f["no_debe_contener"].split(";")]
        checks = [verificar_evidencia(raiz, e, manifiestos, debe[i] if i < len(debe) else "",
                                      no_debe[i] if i < len(no_debe) else "")
                  for i, e in enumerate(evidencias)]
        if estado in ("cumple", "parcial"):
            if not evidencias:
                problemas.append(f"declara '{estado}' sin evidencia")
            for c in checks:
                if not c["ok"]:
                    problemas.append(f"{c['ruta']}: {c['integridad']}; {c['contenido']}")
        for campo in ("brecha", "accion", "responsable", "plazo_dias"):
            if estado in ("parcial", "brecha") and not f[campo].strip():
                problemas.append(f"falta {campo}")
        if f["responsable"].strip() and f["responsable"].strip() not in roles_validos:
            problemas.append(f"responsable '{f['responsable']}' no existe en la matriz RACI")
        if f["plazo_dias"].strip() and not f["plazo_dias"].strip().isdigit():
            problemas.append("plazo no numerico")
        resultado.append({**f, "verificacion": "consistente" if not problemas else "INCONSISTENTE",
                          "problemas": problemas, "checks": checks})
    return resultado


# ---------------------------------------------------------------- matriz RACI (COBIT 5)
def evaluar_raci(filas):
    roles = [c for c in filas[0] if c not in ("proceso", "nombre", "ambito")]
    hallazgos = []
    for f in filas:
        p = f["proceso"]
        asignado = {r: f[r].strip().upper() for r in roles}
        a = [r for r, v in asignado.items() if "A" in v.split("/")]
        rr = [r for r, v in asignado.items() if "R" in v.split("/")]
        if len(a) != 1:
            hallazgos.append(f"{p}: debe tener exactamente un responsable final (A); tiene {len(a)}")
        if not rr:
            hallazgos.append(f"{p}: nadie ejecuta el proceso (R)")
        if f["ambito"] == "gobierno" and a != [ROL_GOBIERNO]:
            hallazgos.append(f"{p}: un proceso de gobierno debe rendir cuentas a {ROL_GOBIERNO}")
        if f["ambito"] in ("supervision", "auditoria"):
            for r in ROLES_OPERACION & set(a + rr):
                hallazgos.append(f"{p}: {r} opera los sistemas y no puede supervisarse a si mismo")
        if f["ambito"] == "gestion" and ROL_AUDITORIA in a + rr:
            hallazgos.append(f"{p}: {ROL_AUDITORIA} pierde independencia si ejecuta procesos de gestion")
    return roles, hallazgos


# ---------------------------------------------------------------- salida
def main(ruta_matriz, ruta_raci, salida=None):
    raiz = raiz_por_defecto()
    raci = leer_csv(ruta_raci)
    roles, hallazgos_raci = evaluar_raci(raci)
    filas = evaluar_matriz(leer_csv(ruta_matriz), raiz, set(roles))

    print(f"Matriz: {ruta_matriz}  (SHA-256 {sha256(ruta_matriz)[:16]}...)")
    print(f"Evidencias buscadas en: {raiz}\n")
    print("Obligaciones y evidencias:")
    for f in filas:
        print(f"  {f['id']} [{f['estado'].upper():7}] {f['norma']}")
        print(f"       {f['obligacion']}")
        for c in f["checks"]:
            print(f"       evidencia {c['ruta']}: {c['integridad']}; {c['contenido']}")
        if f["estado"] != "cumple" or f["brecha"]:
            print(f"       brecha: {f['brecha']}")
            print(f"       accion: {f['accion']} -> {f['responsable']}, {f['plazo_dias']} dias")
        print(f"       verificacion: {f['verificacion']}" + (" - " + "; ".join(f["problemas"]) if f["problemas"] else ""))

    conteo = {e: sum(f["estado"] == e for f in filas) for e in ("cumple", "parcial", "brecha")}
    checks = [c for f in filas for c in f["checks"]]
    print(f"\nResumen: {len(filas)} obligaciones | cumple {conteo['cumple']}, parcial {conteo['parcial']}, "
          f"brecha {conteo['brecha']} | evidencias verificadas {sum(c['ok'] for c in checks)} de {len(checks)} | "
          f"inconsistencias {sum(f['verificacion'] != 'consistente' for f in filas)}")
    print("\nAcciones por responsable:")
    for rol in roles:
        mias = [f for f in filas if f["responsable"] == rol and f["accion"]]
        if mias:
            print(f"  {rol}: " + ", ".join(f"{f['id']} ({f['plazo_dias']} d)" for f in mias))

    print(f"\nMatriz RACI (COBIT 5): {len(raci)} procesos, {len(roles)} roles")
    for f in raci:
        a = next((r for r in roles if "A" in f[r].upper().split("/")), "-")
        print(f"  {f['proceso']:6} {f['ambito']:11} A: {a}")
    print("  Reglas: un solo A por proceso, al menos un R, gobierno rinde cuentas a la direccion,")
    print("          quien opera no se supervisa a si mismo y la auditoria no ejecuta procesos de gestion.")
    print("  " + ("Sin hallazgos." if not hallazgos_raci else "Hallazgos:\n    " + "\n    ".join(hallazgos_raci)))

    if salida:
        destino = Path(salida)
        destino.mkdir(parents=True, exist_ok=True)
        with open(destino / "resultado_cumplimiento.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(["id", "norma", "estado", "evidencia", "integridad", "contenido", "verificacion",
                        "responsable", "plazo_dias"])
            for f in filas:
                w.writerow([f["id"], f["norma"], f["estado"], f["evidencia"],
                            " | ".join(c["integridad"] for c in f["checks"]),
                            " | ".join(c["contenido"] for c in f["checks"]), f["verificacion"],
                            f["responsable"], f["plazo_dias"]])
    return filas, hallazgos_raci


if __name__ == "__main__":
    a = sys.argv[1:]
    filas, hallazgos = main(a[0] if a else BASE / "matriz_cumplimiento.csv",
                            a[1] if len(a) > 1 else BASE / "raci.csv", a[2] if len(a) > 2 else None)
    sys.exit(1 if hallazgos or any(f["verificacion"] != "consistente" for f in filas) else 0)
