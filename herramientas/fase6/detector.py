"""Detector de la fase 6: descargas anomalas, modificaciones masivas y senales de software malicioso.

Uso:  python3 detector.py registros_simulados.csv escenarios.csv carpeta_salida

Reglas
  D0  Referencia: volumen diario de descargas de un usuario mayor a 500 MB (umbral fijo).
  D1  Descarga anomala calibrada: volumen diario mayor a la linea base del propio usuario
      (mediana + 5 x MAD normalizada de los 30 dias anteriores, minimo 200 MB), con el umbral
      multiplicado por 3 en las ventanas de entrega registradas en el calendario de proyectos.
  D2  Modificaciones masivas: 50 o mas cambios de archivos de una misma cuenta en 10 minutos.
      Las cuentas de servicio dentro de su ventana programada se registran como esperadas.
  D3  Senales de software malicioso:
      a) 10 o mas archivos renombrados a extensiones de cifrado en 5 minutos;
      b) creacion de un archivo con nombre de nota de rescate;
      c) comandos asociados a ransomware (borrado de copias de sombra, comandos codificados);
      d) conexiones periodicas a un mismo destino externo (beaconing).
Solo se usan registros simulados; las alertas senalan patrones a investigar.
"""
import csv
import re
import statistics
import sys
from collections import defaultdict
from datetime import date, datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------- parametros
UMBRAL_FIJO_MB = 500
HISTORIAL_DIAS = 30
DIAS_MINIMOS_HISTORIAL = 8
K_MAD = 5
PISO_MB = 200
CALENDARIO_ENTREGAS = {"P03": [date(2026, 10, 19), date(2026, 10, 20)]}
FACTOR_ENTREGA = 3
PROYECTO_DE = {"investigador12": "P01", "investigador13": "P01", "investigador05": "P02", "investigador07": "P02",
               "investigador15": "P02", "investigador03": "P03", "investigador04": "P03", "investigador06": "P03",
               "investigador08": "P04", "investigador11": "P04"}

CAMBIOS = {"FILE_UPDATE", "FILE_RENAME", "FILE_DELETE", "FILE_CREATE"}
UMBRAL_CAMBIOS, VENTANA_CAMBIOS = 50, timedelta(minutes=10)
CUENTAS_SERVICIO = {"svc_backup": (2, 4)}      # cuenta: (hora inicial, hora final) de su ventana programada

EXT_CIFRADO = (".locked", ".enc", ".crypt", ".crypted", ".encrypted")
UMBRAL_EXT, VENTANA_EXT = 10, timedelta(minutes=5)
NOTA_RESCATE = re.compile(r"(rescate|ransom|decrypt|recover|restore_files|how_to)", re.I)
COMANDOS = [r"vssadmin(\.exe)?\s+delete\s+shadows", r"wbadmin(\.exe)?\s+delete", r"bcdedit.*recoveryenabled\s+no",
            r"-enc(odedcommand)?\s"]
BEACON_MIN, BEACON_VENTANA, BEACON_CV = 10, timedelta(hours=1), 0.10

INICIO_EVALUACION = date(2026, 10, 1)


def fuera_de_horario(t):
    return t.weekday() >= 5 or not (7 <= t.hour < 19)


def es_externa(ip):
    return bool(ip) and not ip.startswith(("10.", "192.168.", "172.16."))


# ---------------------------------------------------------------- lectura
def leer(ruta):
    eventos = []
    with open(ruta, newline="", encoding="utf-8") as fh:
        for n, f in enumerate(csv.DictReader(fh), start=2):
            f["t"] = datetime.fromisoformat(f["timestamp"])
            f["mb"] = float(f["size_mb"]) if f["size_mb"] else 0.0
            f["linea"] = n
            eventos.append(f)
    eventos.sort(key=lambda e: (e["t"], e["linea"]))
    return eventos


def alerta(regla, sujeto, inicio, fin, severidad, resumen, motivos, n_eventos):
    return {"regla": regla, "sujeto": sujeto, "inicio": inicio, "fin": fin, "severidad": severidad,
            "resumen": resumen, "motivos": motivos, "eventos": n_eventos}


# ---------------------------------------------------------------- D0 y D1: descargas
def volumenes_diarios(eventos):
    vol = defaultdict(lambda: defaultdict(float))
    detalle = defaultdict(list)
    for e in eventos:
        if e["event"] == "DOWNLOAD":
            vol[e["user"]][e["t"].date()] += e["mb"]
            detalle[(e["user"], e["t"].date())].append(e)
    return vol, detalle


def reglas_descargas(eventos, k=K_MAD, usar_calendario=True):
    vol, detalle = volumenes_diarios(eventos)
    d0, d1 = [], []
    for usuario, dias in vol.items():
        for dia, total in sorted(dias.items()):
            if dia < INICIO_EVALUACION:
                continue
            evs = detalle[(usuario, dia)]
            ini, fin = min(e["t"] for e in evs), max(e["t"] for e in evs)
            nocturna = any(fuera_de_horario(e["t"]) for e in evs)
            if total > UMBRAL_FIJO_MB:
                d0.append(alerta("D0", usuario, ini, fin, "media", f"{total:.0f} MB en el dia (umbral fijo 500 MB)",
                                 [], len(evs)))
            historial = [v for dd, v in dias.items() if dia - timedelta(days=HISTORIAL_DIAS) <= dd < dia]
            motivos = []
            if len(historial) >= DIAS_MINIMOS_HISTORIAL:
                med = statistics.median(historial)
                madn = 1.4826 * statistics.median(abs(v - med) for v in historial)
                umbral = max(PISO_MB, med + k * madn)
                motivos.append(f"linea base: mediana {med:.0f} MB, MADn {madn:.0f} MB")
            else:
                umbral = UMBRAL_FIJO_MB
                motivos.append("historial insuficiente: se usa el umbral fijo")
            if usar_calendario and dia in CALENDARIO_ENTREGAS.get(PROYECTO_DE.get(usuario, ""), []):
                umbral *= FACTOR_ENTREGA
                motivos.append(f"ventana de entrega del proyecto: umbral x{FACTOR_ENTREGA}")
            if total > umbral:
                ips_previas = {e["src_ip"] for (u, dd), lst in detalle.items() if u == usuario and dd < dia
                               for e in lst}
                ip_nueva = any(e["src_ip"] not in ips_previas for e in evs)
                puntos = 1 + nocturna + ip_nueva + (total > 3 * umbral)
                sev = "alta" if puntos >= 3 else "media" if puntos == 2 else "baja"
                motivos += [f"{total:.0f} MB frente a un umbral de {umbral:.0f} MB"]
                motivos += ["fuera de horario"] * nocturna + ["IP de origen nueva"] * ip_nueva
                d1.append(alerta("D1", usuario, ini, fin, sev, f"{total:.0f} MB en el dia (umbral calibrado "
                                 f"{umbral:.0f} MB)", motivos, len(evs)))
    return d0, d1


# ---------------------------------------------------------------- D2: modificaciones masivas
def regla_cambios(eventos):
    alertas, esperadas = [], []
    por_cuenta = defaultdict(list)
    for e in eventos:
        if e["event"] in CAMBIOS and e["t"].date() >= INICIO_EVALUACION:
            por_cuenta[e["user"]].append(e)
    for cuenta, evs in por_cuenta.items():
        i = 0
        while i < len(evs):
            j = i
            while j < len(evs) and evs[j]["t"] - evs[i]["t"] <= VENTANA_CAMBIOS:
                j += 1
            if j - i >= UMBRAL_CAMBIOS:
                # extender la rafaga mientras sigan llegando cambios cercanos
                while j < len(evs) and evs[j]["t"] - evs[j - 1]["t"] <= timedelta(minutes=2):
                    j += 1
                grupo = evs[i:j]
                ini, fin = grupo[0]["t"], grupo[-1]["t"]
                ventana = CUENTAS_SERVICIO.get(cuenta)
                if ventana and ventana[0] <= ini.hour < ventana[1]:
                    esperadas.append(alerta("D2", cuenta, ini, fin, "esperada",
                                            f"{len(grupo)} cambios dentro de la ventana programada", [], len(grupo)))
                else:
                    tipos = sorted({e["event"] for e in grupo})
                    alertas.append(alerta("D2", cuenta, ini, fin, "media",
                                          f"{len(grupo)} cambios de archivos en {int((fin - ini).total_seconds() // 60) + 1} min",
                                          [", ".join(tipos)], len(grupo)))
                i = j
            else:
                i += 1
    return alertas, esperadas


# ---------------------------------------------------------------- D3: senales de malware
def regla_malware(eventos):
    alertas = []
    renombres = defaultdict(list)
    conexiones = defaultdict(list)
    for e in eventos:
        if e["t"].date() < INICIO_EVALUACION:
            continue
        if e["event"] == "FILE_RENAME" and e["file"].lower().endswith(EXT_CIFRADO):
            renombres[e["host"]].append(e)
        if e["event"] == "FILE_CREATE" and NOTA_RESCATE.search(Path(e["file"]).name):
            alertas.append(alerta("D3b", e["user"], e["t"], e["t"], "alta", f"nota de rescate creada: {e['file']}",
                                  [f"equipo {e['host']}, proceso {e['process']}"], 1))
        if e["event"] == "PROCESS_START":
            for patron in COMANDOS:
                if re.search(patron, e["detail"], re.I):
                    alertas.append(alerta("D3c", e["user"], e["t"], e["t"], "alta",
                                          f"comando asociado a ransomware: {e['detail']}",
                                          [f"equipo {e['host']}"], 1))
        if e["event"] == "NET_CONNECT" and es_externa(e["dest_ip"]):
            conexiones[(e["host"], e["dest_ip"])].append(e)
    for host, evs in renombres.items():
        i = 0
        while i < len(evs):
            grupo = [x for x in evs[i:] if x["t"] - evs[i]["t"] <= VENTANA_EXT]
            if len(grupo) >= UMBRAL_EXT:
                resto = [x for x in evs if x["t"] >= grupo[0]["t"] and x["t"] - grupo[-1]["t"] <= VENTANA_EXT]
                alertas.append(alerta("D3a", resto[0]["user"], resto[0]["t"], resto[-1]["t"], "alta",
                                      f"{len(resto)} archivos renombrados a extensiones de cifrado",
                                      [f"equipo {host}, proceso {resto[0]['process']}"], len(resto)))
                i = evs.index(resto[-1]) + 1
            else:
                i += 1
    for (host, dest), evs in conexiones.items():
        i = 0
        while i < len(evs):
            grupo = [x for x in evs[i:] if x["t"] - evs[i]["t"] <= BEACON_VENTANA]
            if len(grupo) >= BEACON_MIN:
                intervalos = [(b["t"] - a["t"]).total_seconds() for a, b in zip(grupo, grupo[1:])]
                media = statistics.mean(intervalos)
                cv = statistics.pstdev(intervalos) / media if media else 1
                if cv < BEACON_CV:
                    alertas.append(alerta("D3d", grupo[0]["user"], grupo[0]["t"], grupo[-1]["t"], "media",
                                          f"{len(grupo)} conexiones a {dest} cada {media:.0f} s (CV {cv:.2f})",
                                          [f"equipo {host}, proceso {grupo[0]['process']}"], len(grupo)))
                    i += len(grupo)
                    continue
            i += 1
    return alertas


# ---------------------------------------------------------------- correlacion y evaluacion
def correlacionar(alertas):
    """Sube a 'alta' una alerta de D2 que coincide con senales de D3 en la misma cuenta (30 min)."""
    for a in alertas:
        if a["regla"] == "D2" and any(b["regla"].startswith("D3") and b["sujeto"] == a["sujeto"]
                                      and abs(b["inicio"] - a["inicio"]) <= timedelta(minutes=30) for b in alertas):
            a["severidad"] = "alta"
            a["motivos"].append("coincide con senales de software malicioso")


def leer_escenarios(ruta):
    with open(ruta, newline="", encoding="utf-8") as fh:
        esc = list(csv.DictReader(fh))
    for s in esc:
        s["inicio"], s["fin"] = datetime.fromisoformat(s["inicio"]), datetime.fromisoformat(s["fin"])
        s["sujetos"] = s["sujetos"].split(",")
    return esc


def asignar(a, escenarios):
    for s in escenarios:
        if a["sujeto"] in s["sujetos"] and a["inicio"] <= s["fin"] and a["fin"] >= s["inicio"]:
            # los escenarios de todo el mes (perfiles) solo cuentan si no hay uno mas especifico
            especificos = [x for x in escenarios if a["sujeto"] in x["sujetos"] and a["inicio"] <= x["fin"]
                           and a["fin"] >= x["inicio"] and (x["fin"] - x["inicio"]).days < 7]
            return especificos[0] if especificos else s
    return None


def evaluar(alertas, escenarios):
    filas = []
    for s in escenarios:
        fila = {"id": s["id"], "tipo": s["tipo"], "descripcion": s["descripcion"]}
        for regla in ("D0", "D1", "D2", "D3"):
            fila[regla] = sum(1 for a in alertas if a["regla"].startswith(regla) and a["escenario"] == s["id"])
        filas.append(fila)
    resumen = {}
    for regla in ("D0", "D1", "D2", "D3"):
        propias = [a for a in alertas if a["regla"].startswith(regla)]
        verdaderas = [a for a in propias if a["escenario"] and
                      next(s for s in escenarios if s["id"] == a["escenario"])["tipo"] == "incidente"]
        incidentes = {a["escenario"] for a in verdaderas}
        resumen[regla] = {"alertas": len(propias), "verdaderas": len(verdaderas),
                          "falsas": len(propias) - len(verdaderas), "incidentes": sorted(incidentes)}
    return filas, resumen


def analizar(ruta_registros, ruta_escenarios):
    eventos = leer(ruta_registros)
    d0, d1 = reglas_descargas(eventos)
    d2, esperadas = regla_cambios(eventos)
    d3 = regla_malware(eventos)
    alertas = d0 + d1 + d2 + d3
    correlacionar(alertas)
    escenarios = leer_escenarios(ruta_escenarios)
    for a in alertas + esperadas:
        s = asignar(a, escenarios)
        a["escenario"] = s["id"] if s else ""
    alertas.sort(key=lambda a: (a["inicio"], a["regla"]))
    filas, resumen = evaluar(alertas, escenarios)
    return eventos, alertas, esperadas, filas, resumen


def main(ruta_registros, ruta_escenarios, salida):
    eventos, alertas, esperadas, filas, resumen = analizar(ruta_registros, ruta_escenarios)
    salida = Path(salida)
    salida.mkdir(parents=True, exist_ok=True)
    with open(salida / "alertas.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["regla", "severidad", "sujeto", "inicio", "fin", "eventos", "resumen", "motivos", "escenario"])
        for a in alertas + esperadas:
            w.writerow([a["regla"], a["severidad"], a["sujeto"], a["inicio"].isoformat(), a["fin"].isoformat(),
                        a["eventos"], a["resumen"], "; ".join(a["motivos"]), a["escenario"]])
    with open(salida / "evaluacion.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["id", "tipo", "descripcion", "D0", "D1", "D2", "D3"], lineterminator="\n")
        w.writeheader()
        w.writerows(filas)

    print(f"Eventos analizados: {len(eventos)} (septiembre como historial, evaluacion en octubre)\n")
    print("Alertas de las reglas calibradas (D1, D2, D3):")
    for a in alertas:
        if a["regla"] != "D0":
            print(f"  [{a['severidad'].upper():5}] {a['inicio']:%Y-%m-%d %H:%M}  {a['regla']:<3} {a['sujeto']:<15} "
                  f"{a['resumen']}  -> {a['escenario'] or 'sin escenario'}")
    print(f"\nRafagas esperadas de cuentas de servicio (no generan alerta): {len(esperadas)}")
    print("\nEvaluacion por escenario (numero de alertas de cada regla):")
    print(f"  {'Esc':<4}{'Tipo':<11}{'D0 fijo':>8}{'D1 calib':>9}{'D2':>4}{'D3':>4}  Descripcion")
    for f in filas:
        print(f"  {f['id']:<4}{f['tipo']:<11}{f['D0']:>8}{f['D1']:>9}{f['D2']:>4}{f['D3']:>4}  {f['descripcion']}")
    print("\nResumen por regla:")
    for regla, r in resumen.items():
        print(f"  {regla}: {r['alertas']} alertas, {r['verdaderas']} sobre incidentes, {r['falsas']} falsas; "
              f"incidentes detectados: {', '.join(r['incidentes']) or 'ninguno'}")
    print("\nLas alertas senalan patrones a investigar; no demuestran intencion ni autoria.")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    main(*sys.argv[1:4])
