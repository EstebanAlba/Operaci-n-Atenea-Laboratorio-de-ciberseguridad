"""Pruebas automaticas de la fase 5. Uso: python3 pruebas.py (desde cualquier carpeta)."""
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import fase5 as f  # noqa: E402

AHORA = f.ahora_utc()
PKI = f.crear_pki(AHORA)
CA_C = PKI["ca"][1]
CORREO = "director01@atenea.test"
DATOS = (f.DATOS / "resultados_P01.csv").read_bytes()
INFORME = (f.DATOS / f.INFORME).read_bytes()
AAD = b"proyecto=P01;archivo=resultados_P01.csv"
BLOB, META = f.cifrar(DATOS, AAD, "frase-prueba")
MAL = bytearray(BLOB)
MAL[30] ^= 1


def paquete():
    return f.empaquetar(INFORME, f.INFORME, *PKI["director01"])


def acepta(paq):
    return f.verificar_paquete(paq, CA_C, CORREO, set(), AHORA)[0]


def hash_ok(paq):
    return dict(f.verificar_paquete(paq, CA_C, CORREO, set(), AHORA)[1])["los hashes de los archivos coinciden con SHA256SUMS"]


def distintos(a, b):
    return bin(int(f.sha256(a), 16) ^ int(f.sha256(b), 16)).count("1")


def caso_cert(nombre):
    for n, cert, rev in f.casos_certificados(PKI, AHORA):
        if n.startswith(nombre):
            return all(ok for _, ok in f.validar_certificado(cert, CA_C, CORREO, rev, AHORA))


def falsificado_con_manifiesto():
    p = paquete()
    p[f.INFORME] = INFORME.replace(b"0.82", b"0.92")
    p["SHA256SUMS"] = f"{f.sha256(p[f.INFORME])}  {f.INFORME}\n".encode()
    return p


def falsificado_con_ca_falsa():
    k, c = f.crear_ca("CA Atenea (ficticia)", AHORA)
    kk, cc = f.emitir("director01", CORREO, k, c, AHORA - timedelta(days=1), AHORA + timedelta(days=30))
    return f.empaquetar(INFORME.replace(b"0.82", b"0.92"), f.INFORME, kk, cc)


def rotacion_ok():
    m2 = f.rotar_kek(META, "frase-prueba", "frase-nueva")
    return f.descifrar(BLOB, m2, "frase-nueva") == DATOS and f.falla_descifrado(BLOB, m2, "frase-prueba")


PRUEBAS = [
    ("Cifrado: descifrar devuelve el original", lambda: f.descifrar(BLOB, META, "frase-prueba") == DATOS),
    ("Cifrado: el texto cifrado no contiene el contenido", lambda: b"control" not in BLOB),
    ("Cifrado: un bit alterado se detecta", lambda: f.falla_descifrado(bytes(MAL), META, "frase-prueba")),
    ("Cifrado: frase incorrecta falla", lambda: f.falla_descifrado(BLOB, META, "otra")),
    ("Cifrado: contexto (AAD) distinto falla", lambda: f.falla_descifrado(BLOB, dict(META, aad="proyecto=P02"), "frase-prueba")),
    ("Cifrado: dos cifrados del mismo archivo difieren", lambda: BLOB != f.cifrar(DATOS, AAD, "frase-prueba")[0]),
    ("Claves: los metadatos no contienen la frase", lambda: "frase-prueba" not in str(META)),
    ("Claves: la rotacion conserva el archivo y cambia la frase", rotacion_ok),
    ("Hash: es determinista", lambda: f.sha256(INFORME) == f.sha256(bytes(INFORME))),
    ("Hash: un caracter cambia unos 128 bits", lambda: 90 < distintos(INFORME, INFORME.replace(b"0.82", b"0.92")) < 166),
    ("Firma: la firma del original es valida", lambda: f.verificar_paquete(paquete(), CA_C, CORREO, set(), AHORA)[1][-2][1]),
    ("Paquete legitimo: aceptado", lambda: acepta(paquete())),
    ("Paquete con archivo cambiado: hash lo detecta", lambda: not hash_ok({**paquete(), f.INFORME: INFORME + b" "})),
    ("Archivo y manifiesto reemplazados: hash pasa pero se rechaza", lambda: hash_ok(falsificado_con_manifiesto()) and not acepta(falsificado_con_manifiesto())),
    ("Firma con CA falsa: firma valida pero se rechaza", lambda: not acepta(falsificado_con_ca_falsa())),
    ("Certificado correcto: aceptado", lambda: caso_cert("Certificado correcto")),
    ("Certificado vencido: rechazado", lambda: not caso_cert("Certificado vencido")),
    ("Certificado de CA falsa: rechazado", lambda: not caso_cert("Emitido por una CA falsa")),
    ("Certificado de otra persona: rechazado", lambda: not caso_cert("Certificado de otra persona")),
    ("Certificado revocado: rechazado", lambda: not caso_cert("Certificado revocado")),
    ("Certificado sin uso de firma: rechazado", lambda: not caso_cert("Uso de clave")),
]

fallas = 0
for nombre, prueba in PRUEBAS:
    try:
        ok = bool(prueba())
    except Exception as e:  # una excepcion inesperada tambien es falla
        ok = False
        nombre += f" (excepcion: {type(e).__name__})"
    fallas += not ok
    print(f"[{'OK' if ok else 'FALLA'}] {nombre}")
print(f"\n{len(PRUEBAS) - fallas} de {len(PRUEBAS)} pruebas correctas")
sys.exit(1 if fallas else 0)
