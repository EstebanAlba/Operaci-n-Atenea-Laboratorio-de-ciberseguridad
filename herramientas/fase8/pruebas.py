"""Pruebas automaticas de la fase 8. Uso: python3 pruebas.py"""
import copy
import sys
from pathlib import Path

BASE = Path(__file__).parent
sys.path.insert(0, str(BASE))
import integrar as it  # noqa: E402

R = it.raiz()
PLAN = it.leer(BASE / "plan.csv")
RUBROS = it.leer(BASE / "presupuesto.csv")
INDIC = it.leer(BASE / "indicadores.csv")
RACI = it.leer(R / "herramientas" / "fase7" / "raci.csv")
ROLES = {c for c in RACI[0] if c not in ("proceso", "nombre", "ambito")}
OBLIG = [f["id"] for f in it.leer(R / "herramientas" / "fase7" / "matriz_cumplimiento.csv")]
BASE_IND = it.linea_base(R)


def plan_con(cambios):
    plan = copy.deepcopy(PLAN)
    for p in plan:
        p.update(cambios.get(p["id"], {}))
    return it.validar_plan(plan, ROLES, OBLIG)


def presupuesto_con(id_, campo, valor):
    rubros = copy.deepcopy(RUBROS)
    for r in rubros:
        if r["id"] == id_:
            r[campo] = valor
    return it.validar_presupuesto(rubros, PLAN)


SUB, RES, H_PRES = it.validar_presupuesto(copy.deepcopy(RUBROS), PLAN)
validas = {p["id"] for p in PLAN if p["valida_sin_causa"] == "si"}
condicionadas = [p for p in PLAN if p["valida_sin_causa"] != "si"]

casos = [
    ("El plan vigente es coherente (responsables, criterios, dependencias y cobertura)",
     not it.validar_plan(PLAN, ROLES, OBLIG)),
    ("El plan cubre las 17 obligaciones de la fase 7 y los 10 riesgos de la fase 6",
     not [h for h in it.validar_plan(PLAN, ROLES, OBLIG) if "no tiene accion" in h]),
    ("Las tres etapas tienen acciones y cada una tiene responsable y criterio de aceptacion",
     {"30", "60", "90"} <= {p["etapa"] for p in PLAN}
     and all(p["responsable"] in ROLES and p["criterio_aceptacion"] for p in PLAN)),
    ("Una accion del dia 30 que depende de una del dia 90 se detecta",
     any("termina despues" in h for h in plan_con({"P03": {"depende_de": "P15"}}))),
    ("Un ciclo de dependencias se detecta", any("ciclo" in h for h in plan_con({"P01": {"depende_de": "P02"}}))),
    ("Si se quita la accion de custodia de claves, el riesgo R10 queda sin cubrir",
     any("R10" in h for h in plan_con({"P12": {"origen": "C17"}}))),
    ("Un responsable que no esta en la RACI se detecta",
     any("RACI" in h for h in plan_con({"P04": {"responsable": "Proveedor"}}))),
    (f"El presupuesto no supera COP 35.000.000 y deja una reserva de al menos 5 % (reserva {it.pesos(RES)})",
     not H_PRES and SUB <= it.TOPE and RES >= it.TOPE * it.RESERVA_MINIMA),
    ("Un presupuesto que supera el tope se detecta", any("supera" in h for h in presupuesto_con("B02", "cantidad", "300")[2])),
    ("Una reserva menor al 5 % se detecta", any("reserva" in h for h in presupuesto_con("B02", "cantidad", "130")[2])),
    ("Cada rubro financia al menos una accion y explica su estimacion",
     all(any(r["id"] in it.lista(p["costo"]) for p in PLAN) and r["base_de_estimacion"] for r in RUBROS)),
    ("Hay al menos cinco indicadores con formula, meta, frecuencia y responsable",
     len([i for i in INDIC if i["formula"] and i["meta_90_dias"] and i["frecuencia"] and i["responsable"]]) >= 5),
    ("Linea base I1: el unico cambio de rol de la muestra no tiene aprobador", BASE_IND["I1"][0].startswith("1 de 1")),
    ("Linea base I3: umbral fijo 1/50 y reglas calibradas 7/8, calculadas con la evidencia de la fase 6",
     "1/50" in BASE_IND["I3"][0] and "7/8" in BASE_IND["I3"][0]),
    ("Linea base I7: 9 de 17 obligaciones cumplidas segun el verificador de la fase 7",
     BASE_IND["I7"][0].startswith("9 de 17")),
    ("Reto: ninguna accion valida depende de una recomendacion sujeta a la causa",
     not any(d.startswith("X") for p in PLAN if p["id"] in validas for d in it.lista(p["depende_de"]))),
    ("Reto: cada recomendacion condicionada depende de la evidencia preservada o del concepto juridico",
     all({"P06", "P07"} & set(it.lista(p["depende_de"])) for p in condicionadas)),
]

ok = 0
for nombre, resultado in casos:
    print(f"[{'OK' if resultado else 'FALLA'}] {nombre}")
    ok += bool(resultado)
print(f"\n{ok} de {len(casos)} pruebas correctas")
sys.exit(0 if ok == len(casos) else 1)
