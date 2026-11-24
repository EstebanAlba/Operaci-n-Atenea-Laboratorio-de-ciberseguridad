"""Pruebas automaticas de la fase 6. Uso: python3 pruebas.py"""
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).parent
sys.path.insert(0, str(BASE))
import detector as det  # noqa: E402

tmp = Path(tempfile.mkdtemp())
for carpeta in ("a", "b"):
    subprocess.run([sys.executable, str(BASE / "generar_registros.py"), str(tmp / carpeta)], check=True,
                   capture_output=True)
REG, ESC = tmp / "a" / "registros_simulados.csv", tmp / "a" / "escenarios.csv"
eventos, alertas, esperadas, filas, resumen = det.analizar(REG, ESC)
por = {f["id"]: f for f in filas}


def de(regla, esc):
    return [a for a in alertas if a["regla"].startswith(regla) and a["escenario"] == esc]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


casos = [
    ("El generador es reproducible: dos ejecuciones dan el mismo SHA-256",
     sha(REG) == sha(tmp / "b" / "registros_simulados.csv")),
    ("El umbral fijo produce 40 o mas falsos positivos en el perfil de descargas grandes (S1)", por["S1"]["D0"] >= 40),
    ("La linea base calibrada no alerta sobre el perfil de descargas grandes (S1)", por["S1"]["D1"] == 0),
    ("El calendario de entregas evita alertas en la semana de entrega de P03 (S2)", por["S2"]["D1"] == 0),
    ("El umbral fijo NO detecta la descarga nocturna de 300 MB de una cuenta liviana (S3)", por["S3"]["D0"] == 0),
    ("La linea base calibrada SI detecta S3", por["S3"]["D1"] == 1),
    ("Ambas reglas detectan la descarga de 1.500 MB desde una IP nueva (S4)", por["S4"]["D0"] >= 1 and por["S4"]["D1"] == 1),
    ("S4 se clasifica con severidad alta (madrugada e IP nueva)", de("D1", "S4")[0]["severidad"] == "alta"),
    ("La copia de seguridad en su ventana programada no genera alertas de D2 (S5)",
     por["S5"]["D2"] == 0 and len([e for e in esperadas if e["sujeto"] == "svc_backup"]) >= 28),
    ("La reorganizacion legitima activa D2 con severidad media y ninguna senal de malware (S8)",
     por["S8"]["D2"] == 1 and de("D2", "S8")[0]["severidad"] == "media" and por["S8"]["D3"] == 0),
    ("Ransomware (S6): extensiones de cifrado, nota de rescate y borrado de copias",
     {a["regla"] for a in de("D3", "S6")} == {"D3a", "D3b", "D3c"}),
    ("Ransomware (S6): D2 sube a severidad alta al coincidir con senales de malware",
     de("D2", "S6")[0]["severidad"] == "alta"),
    ("Beaconing (S7) detectado por la periodicidad de las conexiones", len(de("D3d", "S7")) == 1),
    ("La navegacion web normal no produce alertas de beaconing",
     all(a["escenario"] == "S7" for a in alertas if a["regla"] == "D3d")),
    ("Las reglas calibradas (D1, D2, D3) detectan los cuatro incidentes",
     all(sum(por[s][r] for r in ("D1", "D2", "D3")) > 0 for s in ("S3", "S4", "S6", "S7"))),
    ("Las senales de malware (D3) no tienen falsos positivos", resumen["D3"]["falsas"] == 0),
]
_, d1_sin = det.reglas_descargas(eventos, usar_calendario=False)
casos.append(("Sin calendario de entregas, la regla D1 produce mas alertas en S2",
              any(det.asignar(a, det.leer_escenarios(ESC))["id"] == "S2" for a in d1_sin
                  if det.asignar(a, det.leer_escenarios(ESC)))))

fallas = 0
for texto, ok in casos:
    fallas += not ok
    print(f"[{'OK' if ok else 'FALLA'}] {texto}")
print(f"\n{len(casos) - fallas} de {len(casos)} pruebas correctas")
sys.exit(1 if fallas else 0)
