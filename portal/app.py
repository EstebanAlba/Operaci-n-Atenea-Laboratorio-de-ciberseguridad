"""PORTAL-01 - portal de colaboracion del laboratorio (fase 4).

Toda decision de autorizacion se toma en el servidor y en cada solicitud:
  1. la sesion existe, no expiro y no fue revocada;
  2. la cuenta sigue activa y su acceso no ha vencido (fin del proyecto o del convenio);
  3. la operacion esta permitida para el rol (control vertical);
  4. el recurso pertenece a un proyecto del usuario (control horizontal).
El cliente solo recibe "acceso denegado"; el motivo exacto queda en el registro.
"""
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

import datos
import seguridad as seg

app = FastAPI(title="PORTAL-01 Centro Atenea (laboratorio)")
sesiones = seg.Sesiones()


def cargar_cuentas():
    cuentas = {}
    for usuario, (rol, proyectos, clave, hasta) in datos.CUENTAS.items():
        sal, h = seg.hash_clave(clave)
        cuentas[usuario] = {"rol": rol, "proyectos": list(proyectos), "sal": sal, "hash": h,
                            "acceso_hasta": hasta, "activa": True}
    return cuentas


cuentas = cargar_cuentas()
documentos = {p: dict(d) for p, d in datos.DOCUMENTOS.items()}
publicados = set()


# ---------------------------------------------------------------- autorizacion
def estado_cuenta(usuario):
    c = cuentas.get(usuario)
    if not c:
        return "cuenta inexistente"
    if not c["activa"]:
        return "cuenta desactivada"
    if c["acceso_hasta"] and seg.reloj.ahora() > c["acceso_hasta"]:
        return "acceso vencido (fin del proyecto o del convenio)"
    return None


def autorizar(usuario, operacion, proyecto=None):
    """Devuelve None si se permite, o el motivo de la negacion."""
    motivo = estado_cuenta(usuario)
    if motivo:
        return motivo
    rol = cuentas[usuario]["rol"]
    if operacion not in datos.MATRIZ[rol]:
        return f"operacion '{operacion}' no permitida para el rol {rol}"
    if operacion in datos.OPERACIONES_DE_PROYECTO and proyecto not in cuentas[usuario]["proyectos"]:
        return f"el proyecto {proyecto} no es del usuario"
    return None


def sesion_actual(request: Request):
    cab = request.headers.get("authorization", "")
    token = cab[7:] if cab.lower().startswith("bearer ") else request.cookies.get("sesion")
    sesion, motivo = sesiones.validar(token)
    if not sesion:
        seg.registrar(event="SESSION_REJECTED", user="(sin sesion)", src_ip=request.client.host, decision="denegado",
                      recurso=request.url.path, motivo=motivo)
        raise HTTPException(401, "sesion invalida o expirada")
    sesion["token"] = token
    return sesion


def exigir(request, sesion, operacion, proyecto=None, recurso="", evento="ACCESS"):
    usuario = sesion["usuario"]
    motivo = autorizar(usuario, operacion, proyecto)
    if not motivo and cuentas[usuario]["rol"] in datos.ROLES_ALTO_IMPACTO and not sesion["mfa"]:
        motivo = "operacion de alto impacto sin segundo factor"
    if motivo:
        seg.registrar(event="ACCESS_DENIED", user=usuario, src_ip=request.client.host,
                      role=cuentas.get(usuario, {}).get("rol", ""), decision="denegado", operacion=operacion,
                      recurso=recurso, motivo=motivo, sesion=sesion["huella"][:8])
        raise HTTPException(403, "acceso denegado")


def permitido(request, sesion, evento, operacion, recurso, **extra):
    seg.registrar(event=evento, user=sesion["usuario"], src_ip=request.client.host,
                  role=cuentas[sesion["usuario"]]["rol"], decision="permitido", operacion=operacion,
                  recurso=recurso, sesion=sesion["huella"][:8], **extra)


# ---------------------------------------------------------------- sesion
class Credenciales(BaseModel):
    usuario: str
    clave: str
    codigo_mfa: str | None = None


@app.post("/sesion")
def iniciar_sesion(datos_in: Credenciales, request: Request, response: Response):
    ip = request.client.host
    c = cuentas.get(datos_in.usuario)
    if not c or not seg.verificar_clave(datos_in.clave, c["sal"], c["hash"]):
        seg.registrar(event="LOGIN_FAIL", user=datos_in.usuario, src_ip=ip, decision="denegado",
                      motivo="credenciales invalidas")
        raise HTTPException(401, "credenciales invalidas")
    motivo = estado_cuenta(datos_in.usuario)
    if motivo:
        seg.registrar(event="LOGIN_FAIL", user=datos_in.usuario, src_ip=ip, decision="denegado", motivo=motivo)
        raise HTTPException(403, "acceso denegado")
    con_mfa = False
    if c["rol"] in datos.ROLES_ALTO_IMPACTO:
        if not seg.verificar_totp(datos.SECRETO_MFA_LAB, datos_in.codigo_mfa or ""):
            seg.registrar(event="LOGIN_FAIL", user=datos_in.usuario, src_ip=ip, role=c["rol"], decision="denegado",
                          motivo="segundo factor ausente o invalido")
            raise HTTPException(401, "credenciales invalidas")
        con_mfa = True
    token = sesiones.crear(datos_in.usuario, con_mfa)
    response.set_cookie("sesion", token, httponly=True, secure=True, samesite="strict",
                        max_age=int(seg.DURACION_MAXIMA.total_seconds()), path="/")
    seg.registrar(event="LOGIN_OK", user=datos_in.usuario, src_ip=ip, role=c["rol"], decision="permitido",
                  motivo="con MFA" if con_mfa else "", sesion=sesiones.huella(token)[:8])
    return {"token": token, "rol": c["rol"], "inactividad_max_min": int(seg.INACTIVIDAD.total_seconds() // 60)}


@app.delete("/sesion")
def cerrar_sesion(request: Request, response: Response, sesion=Depends(sesion_actual)):
    sesiones.revocar_token(sesion["token"])
    response.delete_cookie("sesion", path="/")
    permitido(request, sesion, "LOGOUT", "cerrar_sesion", "/sesion")
    return {"ok": True}


# ---------------------------------------------------------------- documentos
def documento(proyecto, nombre):
    if nombre not in documentos.get(proyecto, {}):
        raise HTTPException(404, "documento no encontrado")
    return documentos[proyecto][nombre]


@app.get("/proyectos/{proyecto}/documentos")
def listar(proyecto: str, request: Request, sesion=Depends(sesion_actual)):
    exigir(request, sesion, "leer", proyecto, f"{proyecto}/")
    permitido(request, sesion, "READ", "leer", f"{proyecto}/")
    return sorted(documentos.get(proyecto, {}))


@app.get("/proyectos/{proyecto}/documentos/{nombre}")
def leer(proyecto: str, nombre: str, request: Request, sesion=Depends(sesion_actual)):
    exigir(request, sesion, "leer", proyecto, f"{proyecto}/{nombre}")
    contenido, _ = documento(proyecto, nombre)
    permitido(request, sesion, "READ", "leer", f"{proyecto}/{nombre}", file=nombre)
    return {"documento": nombre, "contenido": contenido}


@app.get("/proyectos/{proyecto}/documentos/{nombre}/descarga")
def descargar(proyecto: str, nombre: str, request: Request, sesion=Depends(sesion_actual)):
    exigir(request, sesion, "descargar", proyecto, f"{proyecto}/{nombre}")
    contenido, mb = documento(proyecto, nombre)
    permitido(request, sesion, "DOWNLOAD", "descargar", f"{proyecto}/{nombre}", file=nombre, size_mb=mb)
    return Response(contenido, media_type="application/octet-stream")


class Edicion(BaseModel):
    contenido: str


@app.put("/proyectos/{proyecto}/documentos/{nombre}")
def editar(proyecto: str, nombre: str, cambio: Edicion, request: Request, sesion=Depends(sesion_actual)):
    exigir(request, sesion, "editar", proyecto, f"{proyecto}/{nombre}")
    _, mb = documento(proyecto, nombre)
    documentos[proyecto][nombre] = (cambio.contenido, mb)
    permitido(request, sesion, "FILE_UPDATE", "editar", f"{proyecto}/{nombre}", file=nombre)
    return {"ok": True}


@app.post("/proyectos/{proyecto}/documentos/{nombre}/publicacion")
def publicar(proyecto: str, nombre: str, request: Request, sesion=Depends(sesion_actual)):
    exigir(request, sesion, "publicar", proyecto, f"{proyecto}/{nombre}")
    documento(proyecto, nombre)
    publicados.add((proyecto, nombre))
    permitido(request, sesion, "PUBLISH", "publicar", f"{proyecto}/{nombre}", file=nombre)
    return {"ok": True}


@app.delete("/proyectos/{proyecto}/documentos/{nombre}")
def eliminar(proyecto: str, nombre: str, request: Request, sesion=Depends(sesion_actual)):
    exigir(request, sesion, "eliminar", proyecto, f"{proyecto}/{nombre}")
    documento(proyecto, nombre)
    del documentos[proyecto][nombre]
    permitido(request, sesion, "DELETE", "eliminar", f"{proyecto}/{nombre}", file=nombre)
    return {"ok": True}


# ---------------------------------------------------------------- administracion
class CambioRol(BaseModel):
    rol: str


@app.put("/admin/usuarios/{usuario}/rol")
def asignar_rol(usuario: str, cambio: CambioRol, request: Request, sesion=Depends(sesion_actual)):
    exigir(request, sesion, "asignar_rol", recurso=f"usuarios/{usuario}")
    if usuario not in cuentas or cambio.rol not in datos.MATRIZ:
        raise HTTPException(404, "usuario o rol inexistente")
    cuentas[usuario]["rol"] = cambio.rol
    # Se registra a nombre del usuario afectado, con el administrador como aprobador (formato de la fase 3)
    seg.registrar(event="ROLE_CHANGE", user=usuario, src_ip=request.client.host, actor=sesion["usuario"],
                  role=cambio.rol, decision="permitido", operacion="asignar_rol", recurso=f"usuarios/{usuario}",
                  sesion=sesion["huella"][:8])
    return {"ok": True}


class Revocacion(BaseModel):
    motivo: str = "fin del proyecto"


@app.post("/usuarios/{usuario}/revocacion")
def revocar(usuario: str, rev: Revocacion, request: Request, sesion=Depends(sesion_actual)):
    """Termina el acceso de una cuenta: vence su autorizacion y cierra todas sus sesiones activas."""
    exigir(request, sesion, "revocar_acceso", recurso=f"usuarios/{usuario}")
    quien = cuentas[sesion["usuario"]]
    objetivo = cuentas.get(usuario)
    if not objetivo:
        raise HTTPException(404, "usuario inexistente")
    if quien["rol"] == "director" and (objetivo["rol"] in ("director", "administrador")
                                       or not set(objetivo["proyectos"]) & set(quien["proyectos"])):
        seg.registrar(event="ACCESS_DENIED", user=sesion["usuario"], src_ip=request.client.host, role="director",
                      decision="denegado", operacion="revocar_acceso", recurso=f"usuarios/{usuario}",
                      motivo="el director solo revoca miembros de sus proyectos", sesion=sesion["huella"][:8])
        raise HTTPException(403, "acceso denegado")
    objetivo["acceso_hasta"] = seg.reloj.ahora()
    cerradas = sesiones.revocar_usuario(usuario)
    permitido(request, sesion, "ACCESS_REVOKED", "revocar_acceso", f"usuarios/{usuario}",
              motivo=f"{rev.motivo}; {cerradas} sesiones cerradas")
    return {"ok": True, "sesiones_cerradas": cerradas}


@app.get("/admin/registros")
def ver_registros(request: Request, sesion=Depends(sesion_actual), ultimos: int = 20):
    exigir(request, sesion, "ver_registros", recurso="registros")
    permitido(request, sesion, "AUDIT_READ", "ver_registros", "registros")
    if not seg.RUTA_REGISTRO.exists():
        return []
    return seg.RUTA_REGISTRO.read_text(encoding="utf-8").splitlines()[-ultimos:]


@app.get("/salud")
def salud():
    return {"ok": True}
