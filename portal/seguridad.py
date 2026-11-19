"""Contrasenas, segundo factor (TOTP), sesiones y registro de accesos sin secretos."""
import base64
import csv
import hashlib
import hmac
import os
import secrets
import struct
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

BOGOTA = timezone(timedelta(hours=-5))
INACTIVIDAD = timedelta(minutes=int(os.getenv("SESION_INACTIVIDAD_MIN", "15")))
DURACION_MAXIMA = timedelta(minutes=int(os.getenv("SESION_MAX_MIN", "480")))
RUTA_REGISTRO = Path(os.getenv("REGISTRO_ACCESOS", "/registros/accesos.csv"))


class Reloj:
    """Reloj del servidor. Las pruebas adelantan el tiempo con `desfase` para probar la expiracion."""
    desfase = timedelta(0)

    def ahora(self):
        return datetime.now(BOGOTA) + self.desfase


reloj = Reloj()


# ---------------------------------------------------------------- contrasenas
def hash_clave(clave, sal=None):
    sal = sal or secrets.token_bytes(16)
    return sal, hashlib.pbkdf2_hmac("sha256", clave.encode(), sal, 100_000)


def verificar_clave(clave, sal, esperado):
    return hmac.compare_digest(hash_clave(clave, sal)[1], esperado)


# ---------------------------------------------------------------- segundo factor (RFC 6238)
def codigo_totp(secreto_b32, instante=None, paso=30, digitos=6):
    instante = instante or reloj.ahora()
    contador = int(instante.timestamp()) // paso
    clave = base64.b32decode(secreto_b32)
    h = hmac.new(clave, struct.pack(">Q", contador), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digitos).zfill(digitos)


def verificar_totp(secreto_b32, codigo):
    ahora = reloj.ahora()
    validos = {codigo_totp(secreto_b32, ahora + timedelta(seconds=s)) for s in (-30, 0, 30)}
    return bool(codigo) and any(hmac.compare_digest(codigo, v) for v in validos)


# ---------------------------------------------------------------- sesiones
class Sesiones:
    """El servidor guarda solo el hash de cada token: si se filtra este almacen, los tokens no sirven."""

    def __init__(self):
        self._datos = {}
        self._lock = threading.Lock()

    @staticmethod
    def huella(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def crear(self, usuario, con_mfa):
        token = secrets.token_urlsafe(32)
        ahora = reloj.ahora()
        with self._lock:
            self._datos[self.huella(token)] = {"usuario": usuario, "creada": ahora, "ultimo_uso": ahora,
                                               "mfa": con_mfa}
        return token

    def validar(self, token):
        """Devuelve (sesion, motivo). Aplica expiracion por inactividad y por duracion maxima."""
        if not token:
            return None, "sin token de sesion"
        h = self.huella(token)
        with self._lock:
            s = self._datos.get(h)
            if not s:
                return None, "token desconocido o revocado"
            ahora = reloj.ahora()
            if ahora - s["ultimo_uso"] > INACTIVIDAD:
                del self._datos[h]
                return None, "sesion expirada por inactividad"
            if ahora - s["creada"] > DURACION_MAXIMA:
                del self._datos[h]
                return None, "sesion expirada por duracion maxima"
            s["ultimo_uso"] = ahora
            return dict(s, huella=h), None

    def revocar_token(self, token):
        with self._lock:
            return self._datos.pop(self.huella(token), None) is not None

    def revocar_usuario(self, usuario):
        with self._lock:
            borrar = [h for h, s in self._datos.items() if s["usuario"] == usuario]
            for h in borrar:
                del self._datos[h]
            return len(borrar)


# ---------------------------------------------------------------- registro de accesos
CAMPOS_REGISTRO = ["timestamp", "event", "user", "src_ip", "actor", "role", "file", "size_mb",
                   "decision", "operacion", "recurso", "motivo", "sesion"]
_lock_registro = threading.Lock()


def registrar(**campos):
    """Escribe una fila en formato compatible con el analizador de la fase 3.
    Nunca recibe contrasenas, tokens ni codigos MFA: la sesion se identifica con 8 caracteres de su huella."""
    fila = {c: "" for c in CAMPOS_REGISTRO}
    fila.update({k: ("" if v is None else v) for k, v in campos.items() if k in fila})
    fila["timestamp"] = reloj.ahora().isoformat(timespec="seconds")
    RUTA_REGISTRO.parent.mkdir(parents=True, exist_ok=True)
    with _lock_registro:
        nuevo = not RUTA_REGISTRO.exists()
        with open(RUTA_REGISTRO, "a", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=CAMPOS_REGISTRO)
            if nuevo:
                w.writeheader()
            w.writerow(fila)
