"""Convierte las salidas XML de Nmap en una tabla de hallazgos ordenada por activo, puerto y prioridad.

Uso (dentro del auditor):  python3 /herramientas/hallazgos.py /evidencias/02_servicios.xml /evidencias/04_detalle_servicios.xml [/evidencias/05_ssh_autenticacion.xml]
Salida: /evidencias/hallazgos.csv y la tabla en pantalla.
Las reglas de prioridad estan al inicio del archivo para que se puedan revisar y ajustar."""
import csv
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ACTIVOS = {"192.168.56.10": "PORTAL-01", "192.168.56.11": "REPO-01"}
ORDEN_PRIORIDAD = {"Alta": 0, "Media": 1, "Baja": 2, "Informativa": 3}


def leer_puertos(archivo):
    """Devuelve una entrada por (ip, puerto) con servicio, version y salida de scripts."""
    datos = {}
    for host in ET.parse(archivo).getroot().iter("host"):
        ip = host.find("address[@addrtype='ipv4']").get("addr")
        for p in host.iter("port"):
            estado = p.find("state").get("state")
            srv = p.find("service")
            clave = (ip, int(p.get("portid")))
            d = datos.setdefault(clave, {"estado": estado, "servicio": "", "version": "", "scripts": {}})
            d["estado"] = estado
            if srv is not None:
                d["servicio"] = srv.get("name", "")
                d["version"] = " ".join(x for x in (srv.get("product"), srv.get("version")) if x)
            for s in p.iter("script"):
                d["scripts"][s.get("id")] = s.get("output", "")
    return datos


def evaluar(ip, puerto, d):
    """Reglas de prioridad. Una exposicion no es una vulnerabilidad confirmada."""
    out = []
    if d["estado"] != "open":
        return [("Puerto no abierto", "Informativa")]
    sc = d["scripts"]
    if d["servicio"] == "ssh":
        metodos = sc.get("ssh-auth-methods")
        if metodos is not None and "password" not in metodos:
            out.append(("Acceso SSH alcanzable desde la red, solo con llave publica", "Media"))
        else:
            out.append(("Acceso administrativo SSH alcanzable desde toda la red", "Alta"))
        if metodos is not None and "password" in metodos:
            out.append(("SSH acepta autenticacion por contrasena", "Alta"))
    if d["servicio"] == "http":
        out.append(("Servicio HTTP sin cifrado (sin TLS)", "Media"))
        if "Index of" in sc.get("http-title", ""):
            out.append(("Listado de directorios habilitado: expone nombres de proyectos y archivos", "Alta"))
        servidor = [l for l in sc.get("http-headers", "").splitlines() if l.strip().lower().startswith("server:")]
        if servidor and any(c.isdigit() for c in servidor[0]):
            out.append((f"Version del servidor anunciada ({servidor[0].strip()})", "Baja"))
    if not out:
        out.append(("Puerto abierto sin regla especifica: revisar manualmente", "Media"))
    return out


def main(archivos):
    datos = {}
    for a in archivos:
        for clave, d in leer_puertos(a).items():
            previo = datos.setdefault(clave, d)
            if previo is not d:
                previo["scripts"].update(d["scripts"])
                previo["version"] = previo["version"] or d["version"]
                previo["servicio"] = previo["servicio"] or d["servicio"]
    filas = []
    for (ip, puerto), d in datos.items():
        for hallazgo, prioridad in evaluar(ip, puerto, d):
            filas.append({"activo": ACTIVOS.get(ip, "No inventariado"), "ip": ip, "puerto": puerto,
                          "servicio": d["servicio"], "version_anunciada": d["version"],
                          "hallazgo": hallazgo, "prioridad": prioridad})
    filas.sort(key=lambda f: (f["activo"], f["puerto"], ORDEN_PRIORIDAD[f["prioridad"]]))
    destino = Path(archivos[0]).parent / "hallazgos.csv"
    with open(destino, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(filas[0]))
        w.writeheader()
        w.writerows(filas)
    for f in filas:
        print(f"{f['activo']:<10} {f['puerto']:>5}  {f['prioridad']:<11} {f['servicio']:<5} {f['version_anunciada']:<28} {f['hallazgo']}")
    print(f"\n{len(filas)} filas escritas en {destino}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
