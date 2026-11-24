"""Integracion de la fase 8 - Operacion Atenea: plan de 90 dias, presupuesto e indicadores.

Comprueba que el plan, el presupuesto y los indicadores sean coherentes entre si y con las fases anteriores:
  - cada accion tiene responsable (de la RACI de la fase 7), criterio de aceptacion y dependencias que
    terminan antes o en la misma etapa, sin ciclos;
  - el plan cubre las 17 obligaciones de la matriz de la fase 7 y los 10 riesgos de la fase 6;
  - el presupuesto no supera COP 35.000.000, deja una reserva y cada rubro financia al menos una accion;
  - la linea base de los indicadores se calcula con las evidencias del repositorio, no se escribe a mano.
Tambien separa las recomendaciones validas aunque no se pruebe la causa de la filtracion (reto).

Uso:  python3 integrar.py [carpeta_salida]
"""
import csv
import os
import re
import sys
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).parent
TOPE = 35_000_000
RESERVA_MINIMA = 0.05
ETAPAS = {"30": 1, "60": 2, "90": 3, "condicionada": 4}
RIESGOS = [f"R{i:02d}" for i in range(1, 11)]


def raiz():
    if os.environ.get("RAIZ"):
        return Path(os.environ["RAIZ"])
    return Path("/") if Path("/evidencias").is_dir() else BASE.parents[1]


def leer(ruta):
    with open(ruta, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def lista(texto):
    return [x.strip() for x in texto.split(";") if x.strip()]


# ---------------------------------------------------------------- validaciones
def validar_plan(plan, roles, obligaciones):
    hallazgos, ids = [], {p["id"]: p for p in plan}
    for p in plan:
        if p["etapa"] not in ETAPAS:
            hallazgos.append(f"{p['id']}: etapa desconocida '{p['etapa']}'")
            continue
        if p["responsable"] not in roles:
            hallazgos.append(f"{p['id']}: el responsable '{p['responsable']}' no esta en la RACI")
        if not p["criterio_aceptacion"].strip():
            hallazgos.append(f"{p['id']}: sin criterio de aceptacion")
        for d in lista(p["depende_de"]):
            if d not in ids:
                hallazgos.append(f"{p['id']}: depende de {d}, que no existe")
            elif ETAPAS.get(ids[d]["etapa"], 9) > ETAPAS[p["etapa"]]:
                hallazgos.append(f"{p['id']} (dia {p['etapa']}) depende de {d}, que termina despues (dia {ids[d]['etapa']})")
    # ciclos
    estado = {}

    def visitar(n, camino):
        if estado.get(n) == 1:
            hallazgos.append("ciclo de dependencias: " + " -> ".join(camino + [n]))
            return
        if estado.get(n) == 2 or n not in ids:
            return
        estado[n] = 1
        for d in lista(ids[n]["depende_de"]):
            visitar(d, camino + [n])
        estado[n] = 2
    for n in ids:
        visitar(n, [])
    origenes = {o for p in plan if p["etapa"] != "condicionada" for o in lista(p["origen"])}
    for c in obligaciones:
        if c not in origenes:
            hallazgos.append(f"la obligacion {c} de la fase 7 no tiene accion en el plan")
    for r in RIESGOS:
        if r not in origenes:
            hallazgos.append(f"el riesgo {r} de la fase 6 no tiene accion en el plan")
    return hallazgos


def validar_presupuesto(rubros, plan):
    hallazgos = []
    for r in rubros:
        r["total"] = int(float(r["cantidad"]) * float(r["valor_unitario"]))
    subtotal = sum(r["total"] for r in rubros)
    reserva = TOPE - subtotal
    usados = {c for p in plan for c in lista(p["costo"])}
    for r in rubros:
        if r["id"] not in usados:
            hallazgos.append(f"el rubro {r['id']} no financia ninguna accion del plan")
        if not r["base_de_estimacion"].strip():
            hallazgos.append(f"el rubro {r['id']} no explica su estimacion")
    for c in usados - {r["id"] for r in rubros}:
        hallazgos.append(f"el plan usa el rubro {c}, que no existe en el presupuesto")
    if subtotal > TOPE:
        hallazgos.append(f"el presupuesto ({subtotal:,}) supera el tope de {TOPE:,}")
    elif reserva < TOPE * RESERVA_MINIMA:
        hallazgos.append(f"la reserva ({reserva:,}) es menor al {RESERVA_MINIMA:.0%} del tope")
    return subtotal, reserva, hallazgos


# ---------------------------------------------------------------- linea base de indicadores
def linea_base(r):
    ev, he = r / "evidencias", r / "herramientas"
    base = {}
    # I1: cambios de rol sin aprobador en la muestra del caso (fase 3)
    cambios = [f for f in leer(he / "fase3" / "datos" / "muestra_enunciado.csv") if f["event"] == "ROLE_CHANGE"]
    sin = sum(not f["actor"] for f in cambios)
    base["I1"] = (f"{sin} de {len(cambios)} ({sin / len(cambios):.0%}) en la muestra del caso",
                  "evidencias de la muestra del enunciado (fase 3)")
    # I2: tiempo entre la revocacion y el primer acceso rechazado en el portal (fase 4)
    acc = leer(ev / "fase4" / "accesos.csv")
    rev = next(f for f in acc if f["event"] == "ACCESS_REVOKED")
    t0 = datetime.fromisoformat(rev["timestamp"])
    rech = next(f for f in acc if f["event"] == "SESSION_REJECTED" and datetime.fromisoformat(f["timestamp"]) >= t0)
    seg = (datetime.fromisoformat(rech["timestamp"]) - t0).total_seconds()
    base["I2"] = (f"{seg:.0f} s en el laboratorio; sin medicion en el centro", "evidencias/fase4/accesos.csv")
    # I3: precision de las alertas (resumen por regla del reporte de la fase 6)
    resumen = {}
    for m in re.finditer(r"(D\d): (\d+) alertas, (\d+) sobre incidentes",
                         (ev / "fase6" / "reporte_deteccion.txt").read_text(encoding="utf-8")):
        resumen[m.group(1)] = (int(m.group(3)), int(m.group(2)))
    v0, t0_ = resumen["D0"]
    v1, t1 = (sum(resumen[d][i] for d in ("D1", "D2", "D3")) for i in (0, 1))
    base["I3"] = (f"umbral fijo {v0}/{t0_} ({v0 / t0_:.0%}); reglas calibradas {v1}/{t1} ({v1 / t1:.1%})",
                  "evidencias/fase6/reporte_deteccion.txt")
    base["I4"] = ("0 % (nadie revisa los registros hoy); se mide desde la accion P09", "caso y fase 1")
    base["I5"] = ("0 restauraciones de prueba realizadas", "caso y fase 1")
    # I6: el portal de la fase 4 exige MFA al administrador
    demo = (ev / "fase4" / "demo.txt").read_text(encoding="utf-8")
    ok = "[OK] esperado 401, obtenido 401 - admin01 sin segundo factor" in demo
    base["I6"] = (("100 % en el laboratorio" if ok else "no demostrado") + "; 0 % en el centro",
                  "evidencias/fase4/demo.txt")
    # I7: obligaciones cumplidas con evidencia verificada (fase 7)
    res = leer(ev / "fase7" / "resultado_cumplimiento.csv")
    cumple = sum(f["estado"] == "cumple" and f["verificacion"] == "consistente" for f in res)
    brechas = sum(f["estado"] == "brecha" for f in res)
    base["I7"] = (f"{cumple} de {len(res)}; {brechas} en brecha", "evidencias/fase7/resultado_cumplimiento.csv")
    return base


# ---------------------------------------------------------------- salida
def pesos(n):
    return f"{n:,.0f}".replace(",", ".")


def main(salida=None):
    r = raiz()
    plan = leer(BASE / "plan.csv")
    rubros = leer(BASE / "presupuesto.csv")
    indicadores = leer(BASE / "indicadores.csv")
    raci = leer(he_ruta(r) / "fase7" / "raci.csv")
    roles = [c for c in raci[0] if c not in ("proceso", "nombre", "ambito")]
    obligaciones = [f["id"] for f in leer(he_ruta(r) / "fase7" / "matriz_cumplimiento.csv")]

    h_plan = validar_plan(plan, set(roles), obligaciones)
    subtotal, reserva, h_pres = validar_presupuesto(rubros, plan)
    base = linea_base(r)

    print("Plan de implementacion")
    for etapa, titulo in (("30", "Dias 1 a 30"), ("60", "Dias 31 a 60"), ("90", "Dias 61 a 90")):
        print(f"\n  {titulo}")
        for p in (x for x in plan if x["etapa"] == etapa):
            dep = f" | depende de {p['depende_de']}" if p["depende_de"] else ""
            print(f"    {p['id']} {p['accion']}")
            print(f"        {p['responsable']}{dep} | origen {p['origen']}" + (f" | {p['costo']}" if p["costo"] else ""))
            print(f"        acepta si: {p['criterio_aceptacion']}")
    cubiertas = {o for p in plan if p["etapa"] != "condicionada" for o in lista(p["origen"])}
    print(f"\n  Cobertura: {sum(c in cubiertas for c in obligaciones)} de {len(obligaciones)} obligaciones de la fase 7, "
          f"{sum(x in cubiertas for x in RIESGOS)} de {len(RIESGOS)} riesgos de la fase 6")
    print("  " + ("Plan coherente." if not h_plan else "Hallazgos:\n    " + "\n    ".join(h_plan)))

    print(f"\nPresupuesto (estimaciones, no cotizaciones; tope COP {pesos(TOPE)})")
    for x in rubros:
        print(f"  {x['id']} {pesos(x['total']):>12}  {x['total'] / TOPE:5.1%}  {x['rubro']}")
    print(f"  {'':3} {pesos(subtotal):>12}  {subtotal / TOPE:5.1%}  Subtotal")
    print(f"  {'':3} {pesos(reserva):>12}  {reserva / TOPE:5.1%}  Reserva para imprevistos")
    print(f"  {'':3} {pesos(TOPE):>12}  100.0%  Total")
    por_etapa = {}
    for p in plan:
        for c in lista(p["costo"]):
            por_etapa.setdefault(c, set()).add(p["etapa"])
    print("  " + ("Presupuesto coherente." if not h_pres else "Hallazgos:\n    " + "\n    ".join(h_pres)))

    print("\nIndicadores (linea base calculada con las evidencias)")
    for i in indicadores:
        lb, fuente = base.get(i["id"], ("sin linea base", ""))
        print(f"  {i['id']} {i['indicador']}: {i['formula']}")
        print(f"      linea base: {lb}  [{fuente}]")
        print(f"      meta a 90 dias: {i['meta_90_dias']} | {i['frecuencia']} | {i['responsable']}")

    print("\nReto: si no puede probarse la causa de la filtracion")
    validas = [p for p in plan if p["valida_sin_causa"] == "si"]
    cond = [p for p in plan if p["valida_sin_causa"] != "si"]
    print(f"  Siguen siendo validas: {len(validas)} acciones ({', '.join(p['id'] for p in validas)}),")
    print("  porque reducen riesgos que existen con o sin filtracion.")
    print(f"  Sujetas a investigacion adicional: {len(cond)}")
    for p in cond:
        print(f"    {p['id']} {p['accion']} -> {p['criterio_aceptacion']}")

    if salida:
        destino = Path(salida)
        destino.mkdir(parents=True, exist_ok=True)
        with open(destino / "presupuesto_calculado.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(["id", "rubro", "total", "porcentaje", "acciones"])
            for x in rubros:
                w.writerow([x["id"], x["rubro"], x["total"], f"{x['total'] / TOPE:.3f}",
                            " ".join(p["id"] for p in plan if x["id"] in lista(p["costo"]))])
            w.writerow(["", "Reserva", reserva, f"{reserva / TOPE:.3f}", ""])
        with open(destino / "linea_base_indicadores.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(["id", "indicador", "linea_base", "fuente", "meta_90_dias"])
            for i in indicadores:
                lb, fuente = base.get(i["id"], ("", ""))
                w.writerow([i["id"], i["indicador"], lb, fuente, i["meta_90_dias"]])
    return h_plan + h_pres


def he_ruta(r):
    return r / "herramientas"


if __name__ == "__main__":
    sys.exit(1 if main(sys.argv[1] if len(sys.argv) > 1 else None) else 0)
