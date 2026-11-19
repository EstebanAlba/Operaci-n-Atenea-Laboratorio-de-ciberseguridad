"""Analizador de registros - Operacion Atenea, fase 3.

Lee un CSV de eventos y aplica tres reglas de deteccion:
  R1  5 o mas fallos de inicio de sesion del mismo usuario en 10 minutos
  R2  descarga de mas de 500 MB
  R3  cambio de rol seguido de una descarga del mismo usuario en 30 minutos

Cada alerta trae fecha, regla, eventos de soporte (con su numero de linea) y un nivel de confianza.
La confianza indica que tan probable es que el patron sea anomalo; NO indica quien uso la cuenta.

Uso:
  python3 analizador.py registros.csv [carpeta_salida]

Formato del CSV (encabezado obligatorio):
  timestamp,event,user,src_ip,actor,role,file,size_mb
  timestamp en ISO 8601 con zona horaria, por ejemplo 2026-10-14T21:04:00-05:00
"""
import csv
import hashlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------- parametros
FALLOS_R1 = 5
VENTANA_R1 = timedelta(minutes=10)
UMBRAL_MB_R2 = 500
VENTANA_R3 = timedelta(minutes=30)
VENTANA_CORRELACION = timedelta(minutes=60)
HISTORIAL_PERFIL = timedelta(days=30)
DESCARGAS_HABITUALES = 3          # descargas grandes previas para considerar el comportamiento habitual
HORARIO_LABORAL = (7, 19)         # de 07:00 a 18:59, lunes a viernes
ZONA_DEFECTO = timezone(timedelta(hours=-5))   # Bogota; se usa solo si la fila no trae zona horaria

ACTIVO_POR_EVENTO = {"LOGIN_FAIL": "AUTH-01", "LOGIN_OK": "AUTH-01", "ROLE_CHANGE": "AUTH-01",
                     "DOWNLOAD": "REPO-01", "FILE_UPDATE": "REPO-01",
                     # eventos adicionales que registra el portal de la fase 4 (no activan reglas)
                     "READ": "REPO-01", "PUBLISH": "REPO-01", "DELETE": "REPO-01", "LOGOUT": "AUTH-01",
                     "SESSION_REJECTED": "AUTH-01", "ACCESS_DENIED": "PORTAL-01",
                     "ACCESS_REVOKED": "AUTH-01", "AUDIT_READ": "MON-01"}
EVENTOS_VALIDOS = set(ACTIVO_POR_EVENTO)
PUNTAJE_BASE = {"R1": 2, "R2": 1, "R3": 2}
NOMBRE_REGLA = {"R1": "Fallos repetidos de inicio de sesion",
                "R2": "Descarga de gran volumen",
                "R3": "Cambio de rol seguido de descarga"}


# ---------------------------------------------------------------- lectura
def leer(ruta):
    """Devuelve (eventos validos, filas descartadas). Nunca se detiene por una fila mala."""
    eventos, descartes = [], []
    with open(ruta, newline="", encoding="utf-8") as fh:
        for n, fila in enumerate(csv.DictReader(fh), start=2):   # la linea 1 es el encabezado
            fila = {k: (v or "").strip() for k, v in fila.items() if k}
            motivo, ev = validar(fila)
            if motivo:
                descartes.append({"linea": n, "motivo": motivo, "contenido": ",".join(fila.values())})
            else:
                ev["linea"] = n
                eventos.append(ev)
    eventos.sort(key=lambda e: (e["t"], e["linea"]))
    return eventos, descartes


def validar(f):
    try:
        t = datetime.fromisoformat(f.get("timestamp", ""))
    except ValueError:
        return "fecha u hora invalida", None
    zona_asumida = t.tzinfo is None
    if zona_asumida:
        t = t.replace(tzinfo=ZONA_DEFECTO)
    evento = f.get("event", "").upper()
    if evento not in EVENTOS_VALIDOS:
        return f"tipo de evento desconocido ({evento or 'vacio'})", None
    if not f.get("user"):
        return "usuario vacio", None
    tam = None
    if evento == "DOWNLOAD":
        try:
            tam = float(f.get("size_mb", ""))
        except ValueError:
            return "tamano de descarga invalido", None
    return None, {"t": t, "evento": evento, "usuario": f["user"], "ip": f.get("src_ip", ""),
                  "actor": f.get("actor", ""), "rol": f.get("role", ""), "archivo": f.get("file", ""),
                  "mb": tam, "zona_asumida": zona_asumida}


# ---------------------------------------------------------------- reglas
def regla_r1(eventos):
    alertas = []
    por_usuario = {}
    for e in eventos:
        if e["evento"] == "LOGIN_FAIL":
            por_usuario.setdefault(e["usuario"], []).append(e)
    for usuario, fallos in por_usuario.items():
        i = 0
        while i < len(fallos):
            ventana = [f for f in fallos[i:] if f["t"] - fallos[i]["t"] <= VENTANA_R1]
            if len(ventana) >= FALLOS_R1:
                alertas.append(nueva("R1", usuario, ventana))
                i += len(ventana)          # no repetir la misma rafaga
            else:
                i += 1
    return alertas


def regla_r2(eventos):
    return [nueva("R2", e["usuario"], [e]) for e in eventos
            if e["evento"] == "DOWNLOAD" and e["mb"] > UMBRAL_MB_R2]


def regla_r3(eventos):
    alertas = []
    for c in (e for e in eventos if e["evento"] == "ROLE_CHANGE"):
        descargas = [e for e in eventos if e["evento"] == "DOWNLOAD" and e["usuario"] == c["usuario"]
                     and timedelta(0) <= e["t"] - c["t"] <= VENTANA_R3]
        if descargas:
            alertas.append(nueva("R3", c["usuario"], [c] + descargas))
    return alertas


def nueva(regla, usuario, soporte):
    return {"regla": regla, "usuario": usuario, "t": soporte[0]["t"], "soporte": soporte,
            "puntaje": PUNTAJE_BASE[regla], "motivos": [f"base {regla} ({PUNTAJE_BASE[regla]:+d})"]}


# ---------------------------------------------------------------- confianza
def fuera_de_horario(t):
    return t.weekday() >= 5 or not (HORARIO_LABORAL[0] <= t.hour < HORARIO_LABORAL[1])


def ajustar(alertas, eventos):
    for a in alertas:
        sop, u = a["soporte"], a["usuario"]
        # El perfil del usuario se arma con su historial ANTERIOR a la hora previa a la alerta,
        # para que los eventos de la misma sesion sospechosa no cuenten como "conocidos".
        previos = [e for e in eventos if e["usuario"] == u and e["t"] < a["t"] - VENTANA_CORRELACION]

        def sumar(valor, motivo):
            a["puntaje"] += valor
            a["motivos"].append(f"{motivo} ({valor:+d})")

        if any(fuera_de_horario(e["t"]) for e in sop):
            sumar(+1, "fuera del horario laboral")
        ips_previas = {e["ip"] for e in previos if e["ip"]}
        ips_alerta = {e["ip"] for e in sop if e["ip"]}
        if ips_previas and ips_alerta - ips_previas:
            sumar(+1, "IP no vista antes para este usuario")
        if any(o is not a and o["usuario"] == u and abs(o["t"] - a["t"]) <= VENTANA_CORRELACION for o in alertas):
            sumar(+1, "otra regla activada para el mismo usuario en 60 min")
        if a["regla"] == "R3":
            if sop[0]["actor"]:
                sumar(-1, f"cambio de rol con aprobador registrado ({sop[0]['actor']})")
            else:
                sumar(+1, "cambio de rol sin aprobador registrado")
        if a["regla"] == "R2":
            grandes = [e for e in previos if e["evento"] == "DOWNLOAD" and e["mb"] > UMBRAL_MB_R2
                       and a["t"] - e["t"] <= HISTORIAL_PERFIL]
            if len(grandes) >= DESCARGAS_HABITUALES:
                sumar(-1, f"{len(grandes)} descargas grandes previas en 30 dias: comportamiento habitual")
        if any((e["evento"] in ("LOGIN_FAIL", "LOGIN_OK", "DOWNLOAD") and not e["ip"]) or e["zona_asumida"]
               for e in sop):
            sumar(-1, "datos incompletos en los eventos de soporte (IP o zona horaria)")
        a["confianza"] = "Alta" if a["puntaje"] >= 4 else "Media" if a["puntaje"] >= 2 else "Baja"
    return sorted(alertas, key=lambda a: (a["t"], a["regla"]))


# ---------------------------------------------------------------- salida
def describir(e):
    extra = ""
    if e["evento"] == "ROLE_CHANGE":
        extra = f" rol={e['rol']} aprobador={e['actor'] or '?'}"
    elif e["evento"] == "DOWNLOAD":
        extra = f" {e['archivo']} {e['mb']:g} MB"
    elif e["evento"] == "FILE_UPDATE":
        extra = f" {e['archivo']}"
    ip = f" ip={e['ip']}" if e["ip"] else " ip=?"
    return f"L{e['linea']} {e['t'].strftime('%H:%M')} {e['evento']}{ip}{extra}"


def sha256(ruta):
    return hashlib.sha256(Path(ruta).read_bytes()).hexdigest()


def analizar(ruta):
    eventos, descartes = leer(ruta)
    alertas = ajustar(regla_r1(eventos) + regla_r2(eventos) + regla_r3(eventos), eventos)
    return eventos, descartes, alertas


def main(ruta, salida=None):
    eventos, descartes, alertas = analizar(ruta)
    print(f"Archivo: {ruta}")
    print(f"SHA-256: {sha256(ruta)}")
    print(f"Filas validas: {len(eventos)} | descartadas: {len(descartes)} | "
          f"con zona horaria asumida: {sum(e['zona_asumida'] for e in eventos)}\n")
    for a in alertas:
        print(f"[{a['confianza'].upper():5}] {a['t'].isoformat()}  {a['regla']} {NOMBRE_REGLA[a['regla']]} - {a['usuario']}")
        for e in a["soporte"]:
            print(f"        soporte: {describir(e)}")
        print(f"        puntaje {a['puntaje']}: {'; '.join(a['motivos'])}")
    if not alertas:
        print("Sin alertas.")
    for d in descartes:
        print(f"[DESCARTADA] linea {d['linea']}: {d['motivo']} -> {d['contenido']}")
    print(f"\nTotal: {len(alertas)} alertas ("
          + ", ".join(f"{c}: {sum(a['confianza'] == c for a in alertas)}" for c in ("Alta", "Media", "Baja")) + ")")
    print("Las alertas senalan patrones a investigar; no demuestran filtracion, intencion ni autoria.")

    if salida:
        destino = Path(salida)
        destino.mkdir(parents=True, exist_ok=True)
        with open(destino / "alertas.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["fecha", "regla", "nombre_regla", "usuario", "confianza", "puntaje", "eventos_soporte", "motivos"])
            for a in alertas:
                w.writerow([a["t"].isoformat(), a["regla"], NOMBRE_REGLA[a["regla"]], a["usuario"], a["confianza"],
                            a["puntaje"], " | ".join(describir(e) for e in a["soporte"]), "; ".join(a["motivos"])])
        with open(destino / "linea_de_tiempo.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["linea", "fecha_hora", "zona_asumida", "usuario", "activo", "evento", "resultado", "detalle"])
            for e in eventos:
                w.writerow([e["linea"], e["t"].isoformat(), "si" if e["zona_asumida"] else "no", e["usuario"],
                            ACTIVO_POR_EVENTO[e["evento"]], e["evento"],
                            "fallido" if e["evento"] == "LOGIN_FAIL" else "exitoso", describir(e)])
        with open(destino / "descartes.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["linea", "motivo", "contenido"])
            w.writeheader()
            w.writerows(descartes)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
