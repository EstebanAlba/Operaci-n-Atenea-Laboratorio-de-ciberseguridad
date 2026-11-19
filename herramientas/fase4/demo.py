"""Demostracion en vivo de la fase 4: el auditor ataca el portal real por la red del laboratorio.
Uso (dentro del auditor):  python3 /herramientas/fase4/demo.py [http://192.168.56.10]
Antes de repetirla, reinicie el portal (docker compose restart portal): la demo revoca a externo01."""
import base64
import hashlib
import hmac
import json
import struct
import sys
import time
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.56.10"
SECRETO_MFA_LAB = "JBSWY3DPEHPK3PXP"     # secreto de laboratorio, igual al del portal
CLAVES = {"investigador07": "Investiga-07!", "admin01": "Admin-01!", "externo01": "Externo-01!",
          "director01": "Director-01!"}


def totp(secreto):
    h = hmac.new(base64.b32decode(secreto), struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)


def pedir(metodo, ruta, token=None, cuerpo=None):
    datos = json.dumps(cuerpo).encode() if cuerpo is not None else None
    req = urllib.request.Request(BASE + ruta, data=datos, method=metodo)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def entrar(usuario, mfa=False):
    cuerpo = {"usuario": usuario, "clave": CLAVES[usuario]}
    if mfa:
        cuerpo["codigo_mfa"] = totp(SECRETO_MFA_LAB)
    estado, texto = pedir("POST", "/sesion", cuerpo=cuerpo)
    return estado, (json.loads(texto)["token"] if estado == 200 else None)


resultados = []


def caso(n, descripcion, esperado, obtenido):
    ok = esperado == obtenido
    resultados.append(ok)
    print(f"{n:>2}. [{'OK' if ok else 'FALLA'}] esperado {esperado}, obtenido {obtenido} - {descripcion}")


print(f"Portal: {BASE}\n")
e, t_inv = entrar("investigador07")
caso(1, "investigador07 inicia sesion", 200, e)
caso(2, "investigador07 lee un documento de su proyecto P01", 200,
     pedir("GET", "/proyectos/P01/documentos/resumen_P01.txt", t_inv)[0])
caso(3, "HORIZONTAL: investigador07 lee un documento del proyecto P02", 403,
     pedir("GET", "/proyectos/P02/documentos/muestra_P02.csv", t_inv)[0])
caso(4, "VERTICAL: investigador07 intenta darse el rol director", 403,
     pedir("PUT", "/admin/usuarios/investigador07/rol", t_inv, {"rol": "director"})[0])
caso(5, "VERTICAL: investigador07 intenta ver los registros de auditoria", 403,
     pedir("GET", "/admin/registros", t_inv)[0])
caso(6, "admin01 sin segundo factor", 401, entrar("admin01")[0])
e, t_adm = entrar("admin01", mfa=True)
caso(7, "admin01 con segundo factor", 200, e)
caso(8, "MINIMO PRIVILEGIO: admin01 intenta leer un documento de investigacion", 403,
     pedir("GET", "/proyectos/P01/documentos/resumen_P01.txt", t_adm)[0])
e, t_ext = entrar("externo01")
caso(9, "externo01 inicia sesion y lee P01", 200, pedir("GET", "/proyectos/P01/documentos/resumen_P01.txt", t_ext)[0])
_, t_dir = entrar("director01")
caso(10, "director01 revoca a externo01 por fin del proyecto", 200,
     pedir("POST", "/usuarios/externo01/revocacion", t_dir, {"motivo": "fin del proyecto"})[0])
caso(11, "RETO: externo01 reutiliza su sesion activa", 401,
     pedir("GET", "/proyectos/P01/documentos/resumen_P01.txt", t_ext)[0])
caso(12, "RETO: externo01 intenta iniciar una sesion nueva", 403, entrar("externo01")[0])
caso(13, "investigador07 cierra sesion", 200, pedir("DELETE", "/sesion", t_inv)[0])
caso(14, "investigador07 reutiliza el token despues de cerrar sesion", 401,
     pedir("GET", "/proyectos/P01/documentos", t_inv)[0])
caso(15, "token alterado", 401, pedir("GET", "/proyectos/P01/documentos", t_dir[:-2] + "xx")[0])
estado, texto = pedir("GET", "/admin/registros?ultimos=10", t_adm)
caso(16, "admin01 consulta los ultimos registros", 200, estado)

print(f"\n{sum(resultados)} de {len(resultados)} casos con el resultado esperado")
print("\nUltimos registros del portal (sin contrasenas, tokens ni codigos MFA):")
for linea in json.loads(texto):
    print("  " + linea)
