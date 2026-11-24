"""Evaluacion de solicitudes de acceso a datos - Operacion Atenea, fase 7 (reto).

Una solicitud de "acceso a todo" no se aprueba ni se rechaza en bloque: se descompone recurso por recurso
y cada uno se decide con tres principios de la Ley 1581 de 2012 y del diseno de la fase 4:
  - finalidad: cada recurso debe tener un motivo propio ligado a una actividad concreta;
  - minimizacion: se entrega la version menos identificable que sirva (agregada o seudonimizada),
    solo lectura salvo aprobacion expresa, y por un tiempo limitado;
  - necesidad legitima: decide el director del proyecto dueno del dato, no el solicitante ni TI.

Uso:  python3 solicitud_acceso.py <solicitud.json> [catalogo.csv]
"""
import csv
import json
import sys
from pathlib import Path

BASE = Path(__file__).parent
MAX_DIAS = 90
DIRECTORES = {"P01": "director01", "P02": "director02", "P03": "director03", "P04": "director04"}
# Operaciones que el rol ya tiene dentro de sus propios proyectos (matriz RBAC de la fase 4)
MATRIZ_RBAC = {"estudiante": {"leer"}, "externo": {"leer"}, "investigador": {"leer", "descargar", "editar"},
               "director": {"leer", "descargar", "editar", "publicar", "eliminar"}}
GENERICOS = ("productividad", "por si acaso", "todo", "todos", "comodidad", "no esperar", "trabajo propio")


def cargar_catalogo(ruta=BASE / "datos" / "catalogo.csv"):
    with open(ruta, newline="", encoding="utf-8") as fh:
        return {f["recurso"]: f for f in csv.DictReader(fh)}


def motivo_valido(motivo):
    m = motivo.strip().lower()
    return len(m) >= 15 and not any(g in m for g in GENERICOS)


def decidir(sol, catalogo):
    pedidos = []
    for r in sol["recursos"]:
        if r["recurso"] == "*":                       # "todo" se descompone en cada recurso del catalogo
            pedidos += [{"recurso": k, "motivo": r.get("motivo", ""), "comodin": True} for k in catalogo]
        else:
            pedidos.append({**r, "comodin": False})
    aprobado = {a.split(":", 1)[1]: a.split(":", 1)[0] for a in sol.get("aprobaciones", []) if ":" in a}
    propias = MATRIZ_RBAC.get(sol["rol"], set())
    dias = min(sol.get("dias") or MAX_DIAS, MAX_DIAS)
    decisiones = []
    for p in pedidos:
        rec, d = p["recurso"], {"recurso": p["recurso"], "condiciones": []}
        info = catalogo.get(rec)
        if not info:
            d.update(decision="DENEGAR", motivo="el recurso no existe en el catalogo")
        elif "reidentificacion" in info["tipo_dato"]:
            d.update(decision="DENEGAR", motivo="la tabla de correspondencia solo la custodia el responsable de "
                     "proteccion de datos; reidentificar exige un procedimiento aparte (Ley 1581, art. 6 lit. e)")
        elif info["proyecto"] in sol["proyectos"]:
            ops = [o for o in sol["operaciones"] if o in propias]
            d.update(decision="YA AUTORIZADO", motivo="es de su proyecto; su rol ya le permite "
                     + ", ".join(ops) + ". La solicitud no cambia nada")
        elif p["comodin"] or not motivo_valido(p.get("motivo", "")):
            d.update(decision="DENEGAR", motivo="sin un motivo propio para este recurso; la productividad no es una "
                     "finalidad que justifique ampliar el acceso (principio de finalidad)")
        elif aprobado.get(rec) != DIRECTORES.get(info["proyecto"]):
            d.update(decision="PENDIENTE", motivo=f"el motivo es especifico, pero falta la aprobacion de "
                     f"{DIRECTORES.get(info['proyecto'], 'el dueno del dato')}, director de {info['proyecto']}")
        else:
            versiones = info["versiones"].split(";")
            d.update(decision="CONCEDER CON CONDICIONES",
                     motivo=f"motivo especifico y aprobado por {aprobado[rec]} (necesidad legitima)")
            d["condiciones"].append(f"vigencia de {dias} dias" + (f" (se pidieron {sol['dias']}; maximo {MAX_DIAS})"
                                                                  if (sol.get("dias") or 0) > MAX_DIAS else ""))
            d["condiciones"].append("solo lectura en linea; la descarga requiere una aprobacion aparte")
            if "sensible" in info["tipo_dato"] or "personal" in info["tipo_dato"]:
                menor = "agregada" if "agregada" in versiones else versiones[0]
                d["condiciones"].append(f"version {menor}; la seudonimizada solo si la agregada no sirve al motivo")
            d["condiciones"].append("cada acceso queda registrado en MON-01 y se revisa al vencer")
        decisiones.append(d)
    return decisiones


def main(ruta_sol, ruta_cat=None):
    sol = json.loads(Path(ruta_sol).read_text(encoding="utf-8"))
    decisiones = decidir(sol, cargar_catalogo(ruta_cat) if ruta_cat else cargar_catalogo())
    print(f"Solicitud {sol['id']} de {sol['solicitante']} ({sol['rol']}, proyectos {', '.join(sol['proyectos'])})")
    print(f"Finalidad declarada: {sol['finalidad']}")
    print(f"Operaciones pedidas: {', '.join(sol['operaciones'])}; vigencia pedida: {sol.get('dias') or 'indefinida'}\n")
    for d in decisiones:
        print(f"  [{d['decision']}] {d['recurso']}")
        print(f"      {d['motivo']}")
        for c in d["condiciones"]:
            print(f"      - {c}")
    conteo = {}
    for d in decisiones:
        conteo[d["decision"]] = conteo.get(d["decision"], 0) + 1
    print(f"\nResultado: {len(decisiones)} recursos evaluados | "
          + ", ".join(f"{k.lower()}: {v}" for k, v in sorted(conteo.items())))
    return decisiones


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(*sys.argv[1:3])
