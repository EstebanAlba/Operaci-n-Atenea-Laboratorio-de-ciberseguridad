#!/usr/bin/env python3
"""Fase 5 - Criptografia y trazabilidad documental (Operacion Atenea).

Todo con archivos y claves FICTICIOS. Las claves privadas se generan en memoria
y nunca se escriben en evidencias.

Uso:
  python3 fase5.py demo [--salida DIR] [--evidencias DIR]
  python3 fase5.py verificar DIR_PAQUETE --esperado CORREO [--huella-ca HEX]
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.x509.oid import NameOID

DATOS = Path(__file__).parent / "datos"
MAGIA = b"ATN1"
AAD_DEK = b"atenea-dek-v1"
FRASE_LAB = os.environ.get("ATENEA_FRASE", "Frase-ficticia-de-laboratorio-Atenea-2026")
INFORME = "informe_P01.txt"


# ---------------------------------------------------------------- utilidades
def sha256(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def ahora_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def bloque(titulo, objetivo, datos, procedimiento, resultado, interpretacion, limitacion):
    """Formato de evidencia exigido: objetivo, datos, procedimiento, resultado, interpretacion, limitacion."""
    lineas = [titulo, "=" * len(titulo), "", f"Objetivo: {objetivo}", f"Datos: {datos}", "Procedimiento:"]
    lineas += [f"  {i}. {p}" for i, p in enumerate(procedimiento, 1)]
    lineas += ["", "Resultado:"] + [f"  {r}" for r in resultado]
    lineas += ["", f"Interpretacion: {interpretacion}", f"Limitacion: {limitacion}", ""]
    return "\n".join(lineas)


# ----------------------------------------------- cifrado autenticado (AES-GCM)
def derivar_kek(frase: str, sal: bytes) -> bytes:
    return Scrypt(salt=sal, length=32, n=2**14, r=8, p=1).derive(frase.encode())


def cifrar(datos: bytes, aad: bytes, frase: str):
    """Cifrado por sobre: una clave de datos (DEK) aleatoria cifra el archivo; la DEK se guarda
    envuelta con una clave derivada de la frase del custodio (KEK), que NO se guarda."""
    dek = AESGCM.generate_key(256)
    nonce_datos, nonce_dek, sal = os.urandom(12), os.urandom(12), os.urandom(16)
    blob = MAGIA + AESGCM(dek).encrypt(nonce_datos, datos, aad)
    kek = derivar_kek(frase, sal)
    meta = {
        "version": 1, "algoritmo": "AES-256-GCM", "kdf": "scrypt n=16384 r=8 p=1",
        "sal": sal.hex(), "nonce_datos": nonce_datos.hex(), "nonce_dek": nonce_dek.hex(),
        "dek_envuelta": AESGCM(kek).encrypt(nonce_dek, dek, AAD_DEK).hex(), "aad": aad.decode(),
    }
    return blob, meta


def descifrar(blob: bytes, meta: dict, frase: str) -> bytes:
    if blob[:4] != MAGIA:
        raise ValueError("formato desconocido")
    kek = derivar_kek(frase, bytes.fromhex(meta["sal"]))
    dek = AESGCM(kek).decrypt(bytes.fromhex(meta["nonce_dek"]), bytes.fromhex(meta["dek_envuelta"]), AAD_DEK)
    return AESGCM(dek).decrypt(bytes.fromhex(meta["nonce_datos"]), blob[4:], meta["aad"].encode())


def rotar_kek(meta: dict, frase_vieja: str, frase_nueva: str) -> dict:
    """Cambia la frase del custodio re-envolviendo la DEK; el archivo cifrado no se toca."""
    kek = derivar_kek(frase_vieja, bytes.fromhex(meta["sal"]))
    dek = AESGCM(kek).decrypt(bytes.fromhex(meta["nonce_dek"]), bytes.fromhex(meta["dek_envuelta"]), AAD_DEK)
    sal, nonce = os.urandom(16), os.urandom(12)
    nuevo = dict(meta, sal=sal.hex(), nonce_dek=nonce.hex())
    nuevo["dek_envuelta"] = AESGCM(derivar_kek(frase_nueva, sal)).encrypt(nonce, dek, AAD_DEK).hex()
    return nuevo


def falla_descifrado(blob, meta, frase) -> bool:
    try:
        descifrar(blob, meta, frase)
        return False
    except (InvalidTag, ValueError):
        return True


# ------------------------------------------------ certificados (mini autoridad)
def _nombre(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Centro Atenea de Innovacion (ficticio)"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def crear_ca(cn, ahora):
    clave = ed25519.Ed25519PrivateKey.generate()
    n = _nombre(cn)
    cert = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(clave.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(ahora - timedelta(days=1)).not_valid_after(ahora + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(clave, None))
    return clave, cert


def emitir(cn, correo, ca_clave, ca_cert, desde, hasta, uso_firma=True):
    clave = ed25519.Ed25519PrivateKey.generate()
    ku = x509.KeyUsage(digital_signature=uso_firma, content_commitment=uso_firma, key_encipherment=False,
                       data_encipherment=False, key_agreement=not uso_firma, key_cert_sign=False,
                       crl_sign=False, encipher_only=False, decipher_only=False)
    cert = (x509.CertificateBuilder().subject_name(_nombre(cn)).issuer_name(ca_cert.subject)
            .public_key(clave.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(desde).not_valid_after(hasta)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(ku, critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(correo)]), critical=False)
            .sign(ca_clave, None))
    return clave, cert


def _vigencia(c):
    desde = getattr(c, "not_valid_before_utc", None) or c.not_valid_before.replace(tzinfo=timezone.utc)
    hasta = getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=timezone.utc)
    return desde, hasta


def validar_certificado(cert, ca_cert, correo_esperado, revocados, ahora):
    """Devuelve una lista de (verificacion, ok). El certificado se acepta solo si todas son True."""
    res = []
    try:
        cert.verify_directly_issued_by(ca_cert)
        emitido = True
    except Exception:
        emitido = False
    res.append(("emitido por la CA de confianza", emitido))
    desde, hasta = _vigencia(cert)
    res.append(("vigente en la fecha actual", desde <= ahora <= hasta))
    try:
        correos = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.RFC822Name)
    except x509.ExtensionNotFound:
        correos = []
    res.append(("identidad esperada (SAN)", correo_esperado in correos))
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        uso = ku.digital_signature and ku.content_commitment
    except x509.ExtensionNotFound:
        uso = False
    res.append(("uso permitido: firma y no repudio", bool(uso)))
    try:
        es_hoja = not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        es_hoja = False
    res.append(("no es una CA", es_hoja))
    res.append(("no aparece en la lista de revocados", cert.serial_number not in revocados))
    return res


def huella(cert) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


# ------------------------------------------------ paquete firmado (manifiesto)
def empaquetar(contenido: bytes, nombre: str, clave, cert) -> dict:
    manifiesto = f"{sha256(contenido)}  {nombre}\n".encode()
    return {nombre: contenido, "SHA256SUMS": manifiesto, "SHA256SUMS.sig": clave.sign(manifiesto), "firmante.pem": pem(cert)}


def verificar_paquete(paq, ca_cert, correo, revocados, ahora, huella_ca=None):
    """Devuelve (aceptado, lista de (paso, ok)). Orden: confianza -> certificado -> firma -> hashes."""
    pasos = []
    if huella_ca is not None:
        pasos.append(("la CA coincide con la huella entregada por otro canal", huella(ca_cert) == huella_ca))
    try:
        cert = x509.load_pem_x509_certificate(paq["firmante.pem"])
    except Exception:
        return False, pasos + [("certificado del firmante legible", False)]
    pasos += [("certificado: " + n, ok) for n, ok in validar_certificado(cert, ca_cert, correo, revocados, ahora)]
    try:
        cert.public_key().verify(paq["SHA256SUMS.sig"], paq["SHA256SUMS"])
        firma = True
    except InvalidSignature:
        firma = False
    pasos.append(("firma valida sobre SHA256SUMS", firma))
    hashes_ok = True
    for linea in paq["SHA256SUMS"].decode().splitlines():
        h, _, nombre = linea.partition("  ")
        hashes_ok &= nombre in paq and sha256(paq[nombre]) == h
    pasos.append(("los hashes de los archivos coinciden con SHA256SUMS", hashes_ok))
    return all(ok for _, ok in pasos), pasos


def fallas(pasos):
    return "; ".join(n for n, ok in pasos if not ok)


# ------------------------------------------------------------------ evidencias
def paso_cifrado(salida):
    datos = (DATOS / "resultados_P01.csv").read_bytes()
    aad = b"proyecto=P01;archivo=resultados_P01.csv"
    blob, meta = cifrar(datos, aad, FRASE_LAB)
    (salida / "resultados_P01.csv.enc").write_bytes(blob)
    (salida / "resultados_P01.csv.enc.json").write_text(json.dumps(meta, indent=2))
    adulterado = bytearray(blob)
    adulterado[40] ^= 1
    meta_aad = dict(meta, aad="proyecto=P02;archivo=resultados_P01.csv")
    blob2, _ = cifrar(datos, aad, FRASE_LAB)
    res = [
        f"Archivo original: {len(datos)} bytes, SHA-256 {sha256(datos)}",
        f"Archivo cifrado:  {len(blob)} bytes, SHA-256 {sha256(blob)} (4 de cabecera + datos + 16 de etiqueta GCM)",
        f"El texto cifrado contiene palabras del original ('control'): {b'control' in blob}",
        f"Descifrado con la frase correcta es identico al original: {descifrar(blob, meta, FRASE_LAB) == datos}",
        f"Un solo bit alterado en el cifrado -> el descifrado falla (etiqueta invalida): {falla_descifrado(bytes(adulterado), meta, FRASE_LAB)}",
        f"Frase incorrecta -> el descifrado falla: {falla_descifrado(blob, meta, 'otra-frase-cualquiera')}",
        f"Datos asociados (AAD) cambiados (proyecto P02) -> falla: {falla_descifrado(blob, meta_aad, FRASE_LAB)}",
        f"Cifrar dos veces el mismo archivo da resultados distintos (nonce unico): {blob != blob2}",
    ]
    return bloque(
        "01 - Cifrado autenticado AES-256-GCM con clave envuelta",
        "Cifrar un archivo ficticio y demostrar que el descifrado solo funciona con la clave, los datos y el contexto correctos.",
        "datos/resultados_P01.csv (12 filas ficticias). Frase del custodio ficticia; no se imprime ni se guarda.",
        ["Se genera una clave de datos (DEK) aleatoria de 256 bits y se cifra el archivo con AES-GCM, ligando el contexto (proyecto y nombre) como dato asociado.",
         "Se deriva una clave de envoltura (KEK) con scrypt a partir de la frase del custodio y se usa para cifrar la DEK.",
         "Se guarda el cifrado (.enc) y los metadatos (.json) con la DEK envuelta; la KEK y la frase no se guardan.",
         "Se intenta descifrar en cinco condiciones: correcta, bit alterado, frase incorrecta, contexto cambiado y repeticion del cifrado."],
        res,
        "GCM es autenticado: no solo oculta el contenido, sino que detecta cualquier cambio en el texto cifrado o en su contexto. La DEK envuelta puede viajar junto al archivo porque sin la KEK no sirve.",
        "La seguridad depende de la frase del custodio. En el laboratorio es una cadena ficticia; en produccion la KEK viviria en un servicio de gestion de claves o un modulo de hardware, no en una frase.")


def paso_hash(salida):
    original = (DATOS / INFORME).read_bytes()
    modificado = original.replace(b"0.82", b"0.92")
    (salida / "informe_P01_modificado.txt").write_bytes(modificado)
    h1, h2 = sha256(original), sha256(modificado)
    bits = bin(int(h1, 16) ^ int(h2, 16)).count("1")
    digitos = sum(a != b for a, b in zip(h1, h2))
    res = [
        f"Original:   {len(original)} bytes  SHA-256 {h1}",
        f"Modificado: {len(modificado)} bytes  SHA-256 {h2}",
        "Cambio aplicado: un solo caracter ('0.82' -> '0.92'); el tamano no cambia.",
        f"Digitos hexadecimales distintos: {digitos} de 64. Bits distintos: {bits} de 256 (esperado ~128 por efecto avalancha).",
        f"Hash recalculado sobre el original sin tocarlo: {sha256(original) == h1} (el hash es determinista)",
    ]
    return bloque(
        "02 - SHA-256 antes y despues de una modificacion",
        "Mostrar que el hash detecta una alteracion minima y como interpretar la diferencia.",
        "datos/informe_P01.txt (informe ficticio) y una copia con un caracter cambiado.",
        ["Se calcula SHA-256 del informe original.", "Se cambia un caracter (la precision 0.82 pasa a 0.92) y se calcula de nuevo.",
         "Se comparan los dos hashes digito a digito y bit a bit."],
        res,
        "Los hashes difieren en aproximadamente la mitad de sus bits aunque el cambio sea de un caracter: no se puede saber que o cuanto cambio, solo que cambio. Sirve para detectar modificaciones, no para repararlas.",
        "Un hash solo es util si se compara con un valor original obtenido por un canal confiable. Si quien modifica el archivo tambien reemplaza el hash publicado, la comparacion no detecta nada (ver evidencia 05).")


def paso_firma(salida, pki, ahora):
    informe = (DATOS / INFORME).read_bytes()
    clave, cert = pki["director01"]
    firma = clave.sign(informe)
    (salida / "informe_P01.txt.sig").write_bytes(firma)
    (salida / "director01.pub.pem").write_bytes(cert.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    pub = cert.public_key()

    def valida(sig, datos, p=pub):
        try:
            p.verify(sig, datos)
            return True
        except InvalidSignature:
            return False

    otra = ed25519.Ed25519PrivateKey.generate().public_key()
    res = [
        f"Algoritmo: Ed25519. Firma de {len(firma)} bytes (hex: {firma.hex()[:48]}...)",
        f"Verificacion con la clave publica de director01 sobre el informe original: {valida(firma, informe)}",
        f"Verificacion sobre el informe con un caracter cambiado: {valida(firma, informe.replace(b'0.82', b'0.92'))}",
        f"Verificacion con la clave publica de otra persona: {valida(firma, informe, otra)}",
        "La clave privada se genero en memoria y no se escribio en evidencias; solo se guardaron la firma y la clave publica.",
    ]
    return bloque(
        "03 - Firma digital de un informe y su verificacion",
        "Firmar un informe ficticio con la clave privada del director y verificarlo con su clave publica.",
        "datos/informe_P01.txt. Par de claves Ed25519 ficticio del usuario director01.",
        ["Se firma el contenido del informe con la clave privada.", "Se verifica la firma con la clave publica y el informe original.",
         "Se repite la verificacion con el informe alterado y con la clave publica de otra persona."],
        res,
        "La firma solo es valida si el contenido es identico y si la clave publica corresponde a quien firmo: prueba integridad y vincula el documento con quien controla la clave privada.",
        "La firma prueba que se uso esa clave privada, no que la persona estaba al teclado: si la clave se roba, el firmante puede negar o un tercero puede firmar. Por eso la irrefutabilidad exige custodia de la clave.")


def casos_certificados(pki, ahora):
    ca_k, ca_c = pki["ca"]
    dia = timedelta(days=1)
    falsa_k, falsa_c = crear_ca("CA Atenea (ficticia)", ahora)  # mismo nombre, otra clave
    _, ok = emitir("director01", "director01@atenea.test", ca_k, ca_c, ahora - dia, ahora + 365 * dia)
    _, venc = emitir("director01", "director01@atenea.test", ca_k, ca_c, ahora - 400 * dia, ahora - 35 * dia)
    _, falso = emitir("director01", "director01@atenea.test", falsa_k, falsa_c, ahora - dia, ahora + 365 * dia)
    _, otro = emitir("investigador07", "investigador07@atenea.test", ca_k, ca_c, ahora - dia, ahora + 365 * dia)
    _, rev = emitir("director01", "director01@atenea.test", ca_k, ca_c, ahora - dia, ahora + 365 * dia)
    _, uso = emitir("director01", "director01@atenea.test", ca_k, ca_c, ahora - dia, ahora + 365 * dia, uso_firma=False)
    return [("Certificado correcto", ok, set()), ("Certificado vencido", venc, set()),
            ("Emitido por una CA falsa con el mismo nombre", falso, set()),
            ("Certificado de otra persona (investigador07)", otro, set()),
            ("Certificado revocado (en la lista de revocados)", rev, {rev.serial_number}),
            ("Uso de clave no permitido para firmar", uso, set())]


def paso_certificados(salida, pki, ahora):
    ca_k, ca_c = pki["ca"]
    _, c = pki["director01"]
    (salida / "ca_atenea.pem").write_bytes(pem(ca_c))
    (salida / "director01.cert.pem").write_bytes(pem(c))
    (salida / "ca_huella_sha256.txt").write_text(huella(ca_c) + "\n")
    desde, hasta = _vigencia(c)
    res = [f"CA ficticia: {ca_c.subject.rfc4514_string()}", f"Huella SHA-256 de la CA (se entrega por otro canal): {huella(ca_c)}",
           f"Certificado de director01: serie {c.serial_number}, vigente {desde:%Y-%m-%d} a {hasta:%Y-%m-%d}",
           "Se valida lo esperado: " + ", ".join(n for n, _ in validar_certificado(c, ca_c, "director01@atenea.test", set(), ahora)), ""]
    esperado = {"Certificado correcto": True}
    for nombre, cert, revocados in casos_certificados(pki, ahora):
        r = validar_certificado(cert, ca_c, "director01@atenea.test", revocados, ahora)
        acept = all(ok for _, ok in r)
        res.append(f"{nombre}: {'ACEPTADO' if acept else 'RECHAZADO'}" + ("" if acept else f"  (falla: {fallas(r)})"))
    return bloque(
        "04 - Certificado digital: que se valida antes de confiar",
        "Comprobar, con una mini autoridad certificadora ficticia, que informacion de un certificado hay que validar antes de confiar en una firma.",
        "CA Atenea ficticia (Ed25519) y certificados emitidos para director01 e investigador07; sin conexion a ninguna autoridad real.",
        ["Se crea una CA autofirmada y se emite un certificado para director01 con uso de firma y no repudio.",
         "Se validan seis cosas: emisor, vigencia, identidad, uso de clave, que no sea una CA y que no este revocado.",
         "Se repite la validacion con cinco certificados defectuosos, cada uno con una falla distinta."],
        res,
        "Un certificado es una afirmacion firmada por una CA: 'esta clave publica pertenece a esta identidad'. Cada caso defectuoso falla en la verificacion que le corresponde; la CA falsa se detecta aunque lleve el mismo nombre, porque la firma del emisor no coincide.",
        "Solo se probo la revocacion con una lista simulada (no CRL ni OCSP reales) y la huella de la CA debe llegar por un canal distinto al del paquete, porque quien controla la CA controla la confianza.")


def paso_hash_vs_autenticidad(salida, pki, ahora):
    ca_k, ca_c = pki["ca"]
    clave, cert = pki["director01"]
    informe = (DATOS / INFORME).read_bytes()
    falso = informe.replace(b"0.82", b"0.92")
    legit = empaquetar(informe, INFORME, clave, cert)
    for n, b in legit.items():
        (salida / "paquete_firmado").mkdir(exist_ok=True)
        (salida / "paquete_firmado" / n).write_bytes(b)
    (salida / "paquete_firmado" / "ca_atenea.pem").write_bytes(pem(ca_c))
    correo = "director01@atenea.test"

    b = dict(legit, **{INFORME: falso})                                          # B: cambia el archivo, no el manifiesto
    c = dict(b, SHA256SUMS=f"{sha256(falso)}  {INFORME}\n".encode())             # C: cambia archivo y manifiesto
    atk_k, atk_ca = crear_ca("CA Atenea (ficticia)", ahora)
    atk_clave, atk_cert = emitir("director01", correo, atk_k, atk_ca, ahora - timedelta(days=1), ahora + timedelta(days=365))
    d = empaquetar(falso, INFORME, atk_clave, atk_cert)                          # D: firma propia con certificado de CA falsa
    e = dict(c, **{"SHA256SUMS.sig": atk_clave.sign(c["SHA256SUMS"])})           # E: firma propia pero certificado real
    escenarios = [("A. Paquete legitimo", legit), ("B. Archivo cambiado, manifiesto intacto", b),
                  ("C. Archivo y manifiesto de hashes reemplazados", c),
                  ("D. Atacante firma con su propia CA falsa", d),
                  ("E. Atacante firma con su clave pero reutiliza el certificado real", e)]
    res = []
    for nombre, paq in escenarios:
        acept, pasos = verificar_paquete(paq, ca_c, correo, set(), ahora)
        hashes = dict(pasos)["los hashes de los archivos coinciden con SHA256SUMS"]
        firma = dict(pasos)["firma valida sobre SHA256SUMS"]
        cert_ok = all(ok for n, ok in pasos if n.startswith("certificado"))
        res.append(f"{nombre}: hashes={'OK' if hashes else 'FALLA'} | firma={'OK' if firma else 'FALLA'} | "
                   f"certificado={'OK' if cert_ok else 'FALLA'} -> {'ACEPTADO' if acept else 'RECHAZADO'}")
    res += ["", "En C el archivo falso 'pasa' la comprobacion de hash (es consistente con su manifiesto) pero no es autentico.",
            "En D la firma es matematicamente valida, pero el certificado no lo emitio la CA de confianza."]
    return bloque(
        "05 - Un archivo puede conservar su hash y no ser autentico",
        "Diferenciar integridad tecnica (el hash coincide), autenticidad del emisor (la firma y el certificado) e irrefutabilidad.",
        "Paquete con el informe ficticio, su manifiesto SHA256SUMS firmado por director01 y cuatro variantes manipuladas.",
        ["Se firma el manifiesto de hashes (no cada archivo) y se empaqueta junto con el certificado.",
         "Se construyen cuatro manipulaciones, de la mas simple a la mas elaborada.",
         "Se aplica el procedimiento completo: certificado, firma sobre el manifiesto y hashes de los archivos."],
        res,
        "El hash prueba integridad frente a un valor de referencia, pero no dice quien lo produjo. La firma vincula el manifiesto con una clave; el certificado vincula esa clave con una identidad avalada por una CA. Solo con las tres capas el paquete falso queda rechazado en todos los casos.",
        "El atacante supuesto no tiene la clave privada de director01 ni controla la CA de confianza. Si cualquiera de las dos se compromete, las verificaciones aceptarian el falso.")


def paso_claves(salida):
    datos = (DATOS / "resultados_P01.csv").read_bytes()
    blob, meta = cifrar(datos, b"proyecto=P01;archivo=resultados_P01.csv", FRASE_LAB)
    nueva = FRASE_LAB + "-rotada"
    meta2 = rotar_kek(meta, FRASE_LAB, nueva)
    res = [
        f"Hash del archivo cifrado antes de la rotacion: {sha256(blob)}",
        f"El archivo cifrado no se modifico: hash despues = {sha256(blob)} (solo cambian los metadatos).",
        f"DEK envuelta antes: {meta['dek_envuelta'][:32]}...  despues: {meta2['dek_envuelta'][:32]}...",
        f"Frase anterior ya no descifra: {falla_descifrado(blob, meta2, FRASE_LAB)}",
        f"Frase nueva descifra y recupera el original: {descifrar(blob, meta2, nueva) == datos}",
        f"Metadatos guardados junto al archivo contienen la frase o la KEK: {FRASE_LAB in json.dumps(meta2)}",
    ]
    return bloque(
        "06 - Gestion de claves: rotacion sin recifrar los datos",
        "Mostrar que la clave que protege el archivo puede cambiarse sin volver a cifrar los datos y sin guardarla junto a ellos.",
        "El archivo cifrado de la evidencia 01 (se cifra de nuevo en memoria) y dos frases ficticias de custodio.",
        ["Se cifra el archivo con una DEK envuelta por la KEK derivada de la frase.", "Se re-envuelve la DEK con una frase nueva.",
         "Se comprueba que la frase vieja deja de servir, la nueva funciona y el archivo cifrado no cambio."],
        res,
        "La rotacion de la KEK es barata (se re-envuelve una clave de 32 bytes), asi que es viable hacerla al salir un custodio o ante sospecha de exposicion.",
        "Rotar la KEK no invalida copias de la DEK que ya se hubieran robado: si la DEK se expone, hay que recifrar los datos con una DEK nueva.")


def paso_firma_registros(salida, pki, evidencias, ahora):
    ruta = Path(evidencias) / "fase3" / "hashes_registros.txt"
    if not ruta.exists():
        return bloque("07 - Firma de los hashes de los registros de la fase 3", "Omitido.", "No existe " + str(ruta),
                      ["Ejecute antes la fase 3."], ["Sin resultados."], "-", "-")
    datos = ruta.read_bytes()
    clave, cert = pki["admin01"]
    firma = clave.sign(datos)
    (salida / "hashes_registros.txt.sig").write_bytes(firma)
    (salida / "admin01.cert.pem").write_bytes(pem(cert))
    ca_c = pki["ca"][1]
    pasos = validar_certificado(cert, ca_c, "admin01@atenea.test", set(), ahora)
    try:
        cert.public_key().verify(firma, datos)
        ok = True
    except InvalidSignature:
        ok = False
    try:
        cert.public_key().verify(firma, datos + b"x")
        ok2 = True
    except InvalidSignature:
        ok2 = False
    res = [f"Archivo firmado: evidencias/fase3/hashes_registros.txt ({len(datos)} bytes, SHA-256 {sha256(datos)})",
           f"Certificado de admin01 valido: {all(o for _, o in pasos)}", f"Firma valida sobre el archivo original: {ok}",
           f"Firma valida si se agrega un caracter al archivo: {ok2}"]
    return bloque(
        "07 - Firma de los hashes de los registros de la fase 3",
        "Complementar los hashes de los registros (fase 3) con una firma, de modo que alguien que los reemplace junto con sus hashes sea detectado.",
        "evidencias/fase3/hashes_registros.txt y el certificado ficticio de admin01 (administrador tecnologico).",
        ["Se firma la lista de hashes de los CSV con la clave de admin01.", "Se valida su certificado y la firma.", "Se altera el archivo y se verifica de nuevo."],
        res,
        "La lista de hashes de la fase 3 prueba que los CSV no cambiaron respecto a esa lista; la firma hace que la lista misma no pueda reemplazarse sin la clave de admin01.",
        "Es un respaldo de integridad, no prueba de que los registros originales sean veraces: eso depende de cuando y donde se capturaron.")


# ------------------------------------------------------------------------- CLI
def crear_pki(ahora):
    ca_k, ca_c = crear_ca("CA Atenea (ficticia)", ahora)
    pki = {"ca": (ca_k, ca_c)}
    for cn in ("director01", "admin01"):
        pki[cn] = emitir(cn, f"{cn}@atenea.test", ca_k, ca_c, ahora - timedelta(days=1), ahora + timedelta(days=365))
    return pki


def cmd_demo(args):
    salida = Path(args.salida)
    salida.mkdir(parents=True, exist_ok=True)
    ahora = ahora_utc()
    pki = crear_pki(ahora)
    pasos = [("01_cifrado.txt", lambda: paso_cifrado(salida)), ("02_hash.txt", lambda: paso_hash(salida)),
             ("03_firma.txt", lambda: paso_firma(salida, pki, ahora)),
             ("04_certificados.txt", lambda: paso_certificados(salida, pki, ahora)),
             ("05_hash_vs_autenticidad.txt", lambda: paso_hash_vs_autenticidad(salida, pki, ahora)),
             ("06_claves_rotacion.txt", lambda: paso_claves(salida)),
             ("07_firma_hashes_fase3.txt", lambda: paso_firma_registros(salida, pki, args.evidencias, ahora))]
    for nombre, f in pasos:
        texto = f()
        (salida / nombre).write_text(texto, encoding="utf-8")
        print(texto)


def cmd_verificar(args):
    d = Path(args.paquete)
    paq = {p.name: p.read_bytes() for p in d.iterdir() if p.is_file()}
    ca = x509.load_pem_x509_certificate(paq.pop("ca_atenea.pem"))
    acept, pasos = verificar_paquete(paq, ca, args.esperado, set(), ahora_utc(), args.huella_ca)
    for n, ok in pasos:
        print(f"  [{'OK' if ok else 'FALLA'}] {n}")
    print("RESULTADO:", "ACEPTADO" if acept else "RECHAZADO")
    sys.exit(0 if acept else 1)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo")
    d.add_argument("--salida", default="/evidencias/fase5")
    d.add_argument("--evidencias", default="/evidencias")
    d.set_defaults(f=cmd_demo)
    v = sub.add_parser("verificar")
    v.add_argument("paquete")
    v.add_argument("--esperado", required=True)
    v.add_argument("--huella-ca")
    v.set_defaults(f=cmd_verificar)
    args = p.parse_args()
    args.f(args)


if __name__ == "__main__":
    main()
