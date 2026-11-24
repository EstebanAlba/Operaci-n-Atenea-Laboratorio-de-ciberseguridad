"""Genera los registros simulados de la fase 6 y la lista de escenarios con su etiqueta real.

Uso:  python3 generar_registros.py <carpeta_salida>
Salida: registros_simulados.csv y escenarios.csv

Los datos cubren del 1 de septiembre al 31 de octubre de 2026. Septiembre solo sirve como historial
para calibrar los perfiles; la evaluacion se hace sobre octubre. La semilla es fija: dos ejecuciones
producen exactamente el mismo archivo (mismo SHA-256).
"""
import csv
import random
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

BOGOTA = timezone(timedelta(hours=-5))
SEMILLA = 2026
INICIO, FIN = date(2026, 9, 1), date(2026, 10, 31)
CAMPOS = ["timestamp", "event", "user", "host", "src_ip", "dest_ip", "file", "size_mb", "process", "detail"]

# usuario: (proyecto, equipo, IP, descarga diaria minima y maxima en MB)
USUARIOS = {
    "investigador12": ("P01", "EQ-INV12", "10.1.2.30", 700, 1300),   # imagenes: descargas grandes habituales
    "investigador13": ("P01", "EQ-INV13", "10.1.2.31", 650, 1200),
    "investigador05": ("P02", "EQ-INV05", "10.1.2.17", 20, 120),
    "investigador07": ("P02", "EQ-INV07", "10.1.2.8", 30, 150),
    "investigador15": ("P02", "EQ-INV15", "10.1.2.20", 20, 110),
    "investigador03": ("P03", "EQ-INV03", "10.1.2.14", 100, 300),
    "investigador04": ("P03", "EQ-INV04", "10.1.2.15", 90, 280),
    "investigador06": ("P03", "EQ-INV06", "10.1.2.16", 110, 320),
    "investigador08": ("P04", "EQ-INV08", "10.1.2.22", 50, 150),
    "investigador11": ("P04", "EQ-INV11", "10.1.2.25", 30, 100),
}
ENTREGA_P03 = (date(2026, 10, 19), date(2026, 10, 20))
SITIOS_WEB = ["151.101.1.69", "142.250.78.14", "13.107.42.14", "104.16.132.229", "185.199.108.153",
              "52.84.150.39", "34.107.221.82"]

r = random.Random(SEMILLA)
filas = []


def ts(d, h, m, s=0):
    return datetime(d.year, d.month, d.day, h, m, s, tzinfo=BOGOTA)


def evento(t, ev, user, host="", src="", dest="", archivo="", mb="", proceso="", detail=""):
    filas.append({"timestamp": t.isoformat(), "event": ev, "user": user, "host": host, "src_ip": src,
                  "dest_ip": dest, "file": archivo, "size_mb": mb, "process": proceso, "detail": detail})


def dia_laboral(d):
    return d.weekday() < 5


# ---------------------------------------------------------------- actividad normal
d = INICIO
while d <= FIN:
    for u, (proy, eq, ip, lo, hi) in USUARIOS.items():
        if not dia_laboral(d):
            continue
        evento(ts(d, 8, r.randint(0, 50)), "LOGIN_OK", u, eq, ip)
        total = r.randint(lo, hi)
        if proy == "P03" and d in ENTREGA_P03:
            total *= 3                                            # S2: semana de entrega del proyecto P03
        elif r.random() < 0.05:
            total = int(total * r.uniform(1.5, 2.5))              # picos legitimos ocasionales (un lote grande)
        partes = r.randint(1, 4)
        for i in range(partes):
            mb = round(total / partes + r.uniform(-5, 5), 1)
            evento(ts(d, r.randint(9, 17), r.randint(0, 59), r.randint(0, 59)), "DOWNLOAD", u, eq, ip,
                   archivo=f"{proy}/datos/lote_{d:%m%d}_{i}.zip", mb=max(mb, 1))
        for _ in range(r.randint(3, 10)):                         # ediciones normales, espaciadas
            evento(ts(d, r.randint(9, 17), r.randint(0, 59), r.randint(0, 59)), "FILE_UPDATE", u, eq, ip,
                   archivo=f"{proy}/trabajo/documento_{r.randint(1, 40)}.docx")
        for _ in range(r.randint(5, 15)):                         # navegacion web irregular
            evento(ts(d, r.randint(8, 18), r.randint(0, 59), r.randint(0, 59)), "NET_CONNECT", u, eq, ip,
                   dest=r.choice(SITIOS_WEB), proceso="navegador.exe")
    # S5: copia de seguridad nocturna, todos los dias, 02:10 a 02:40
    for i in range(300):
        evento(ts(d, 2, 10) + timedelta(seconds=6 * i), "FILE_UPDATE", "svc_backup", "BACKUP-01", "10.1.0.5",
               archivo=f"respaldo/{d:%Y%m%d}/bloque_{i:03d}.bak", proceso="respaldo.service")
    d += timedelta(days=1)

# ---------------------------------------------------------------- escenarios inyectados
# S3: cuenta con perfil liviano descarga 300 MB de noche (por debajo del umbral fijo de 500 MB)
for t, mb, f in [(ts(date(2026, 10, 22), 23, 5), 150, "P02/datos/historico_completo.zip"),
                 (ts(date(2026, 10, 22), 23, 9), 150, "P02/modelos/modelo_final.bin")]:
    evento(t, "DOWNLOAD", "investigador05", "EQ-INV05", "10.1.2.17", archivo=f, mb=mb)

# S4: descarga masiva de madrugada en domingo desde una IP nueva
evento(ts(date(2026, 10, 25), 1, 58), "LOGIN_OK", "investigador15", "EQ-EXT", "203.0.113.45")
for k, mb in enumerate([600, 500, 400]):
    evento(ts(date(2026, 10, 25), 2, 2 + 4 * k), "DOWNLOAD", "investigador15", "EQ-EXT", "203.0.113.45",
           archivo=f"P02/resultados/parte_{k + 1}.zip", mb=mb)

# S6: ransomware en el equipo de investigador08
t0 = ts(date(2026, 10, 27), 15, 10)
evento(t0, "PROCESS_START", "investigador08", "EQ-INV08", "10.1.2.22", proceso="factura_octubre.exe",
       detail="factura_octubre.exe abierto desde adjunto de correo")
evento(t0 + timedelta(seconds=20), "PROCESS_START", "investigador08", "EQ-INV08", "10.1.2.22",
       proceso="cmd.exe", detail="vssadmin delete shadows /all /quiet")
for i in range(200):
    evento(t0 + timedelta(seconds=40 + i), "FILE_RENAME", "investigador08", "EQ-INV08", "10.1.2.22",
           archivo=f"P04/datos/archivo_{i:03d}.csv.locked", proceso="factura_octubre.exe",
           detail=f"P04/datos/archivo_{i:03d}.csv -> P04/datos/archivo_{i:03d}.csv.locked")
evento(t0 + timedelta(minutes=4, seconds=5), "FILE_CREATE", "investigador08", "EQ-INV08", "10.1.2.22",
       archivo="P04/datos/LEEME_RESCATE.txt", proceso="factura_octubre.exe")

# S7: conexiones periodicas (beaconing) cada 60 s desde el equipo de investigador11, domingo de noche
for i in range(31):
    evento(ts(date(2026, 10, 18), 20, 0) + timedelta(seconds=60 * i + r.randint(-2, 2)), "NET_CONNECT",
           "investigador11", "EQ-INV11", "10.1.2.25", dest="198.51.100.23", proceso="actualizador.exe")

# S8: reorganizacion legitima de carpetas: 80 renombrados en 8 minutos, sin cambio de extension
for i in range(80):
    evento(ts(date(2026, 10, 9), 10, 0) + timedelta(seconds=6 * i), "FILE_RENAME", "investigador03", "EQ-INV03",
           "10.1.2.14", archivo=f"P03/2026/datos/serie_{i:02d}.csv", proceso="explorador.exe",
           detail=f"P03/datos/serie_{i:02d}.csv -> P03/2026/datos/serie_{i:02d}.csv")

ESCENARIOS = [
    ("S1", "legitimo", "Perfil de descargas grandes habituales (grupo de imagenes P01)", "investigador12,investigador13",
     "2026-10-01T00:00:00-05:00", "2026-10-31T23:59:59-05:00"),
    ("S2", "legitimo", "Semana de entrega del proyecto P03: el grupo triplica sus descargas",
     "investigador03,investigador04,investigador06", "2026-10-19T00:00:00-05:00", "2026-10-20T23:59:59-05:00"),
    ("S3", "incidente", "Cuenta de perfil liviano descarga 300 MB de noche", "investigador05",
     "2026-10-22T23:00:00-05:00", "2026-10-22T23:59:59-05:00"),
    ("S4", "incidente", "Descarga de 1.500 MB de madrugada, en domingo y desde una IP nueva", "investigador15",
     "2026-10-25T01:50:00-05:00", "2026-10-25T02:30:00-05:00"),
    ("S5", "legitimo", "Copia de seguridad nocturna: 300 archivos en 30 minutos cada noche", "svc_backup",
     "2026-10-01T00:00:00-05:00", "2026-10-31T23:59:59-05:00"),
    ("S6", "incidente", "Ransomware: borrado de copias, 200 archivos cifrados y nota de rescate", "investigador08",
     "2026-10-27T15:10:00-05:00", "2026-10-27T15:20:00-05:00"),
    ("S7", "incidente", "Conexiones periodicas cada 60 s a un destino externo (beaconing)", "investigador11",
     "2026-10-18T20:00:00-05:00", "2026-10-18T20:35:00-05:00"),
    ("S8", "legitimo", "Reorganizacion de carpetas: 80 archivos movidos en 8 minutos", "investigador03",
     "2026-10-09T10:00:00-05:00", "2026-10-09T10:10:00-05:00"),
]

if __name__ == "__main__":
    destino = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    destino.mkdir(parents=True, exist_ok=True)
    filas.sort(key=lambda f: (f["timestamp"], f["user"], f["file"]))
    with open(destino / "registros_simulados.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CAMPOS, lineterminator="\n")
        w.writeheader()
        w.writerows(filas)
    with open(destino / "escenarios.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["id", "tipo", "descripcion", "sujetos", "inicio", "fin"])
        w.writerows(ESCENARIOS)
    print(f"{len(filas)} eventos y {len(ESCENARIOS)} escenarios escritos en {destino}")
