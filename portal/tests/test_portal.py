"""Bateria de pruebas del portal (fase 4). Ejecutar dentro del contenedor del portal:  pytest -v"""
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app as portal
import datos
import seguridad as seg

cliente = TestClient(portal.app)
REGISTRO = Path(seg.RUTA_REGISTRO)


@pytest.fixture(autouse=True)
def estado_limpio():
    """Cada prueba arranca con cuentas, documentos, sesiones y reloj originales."""
    portal.cuentas.clear()
    portal.cuentas.update(portal.cargar_cuentas())
    portal.documentos.clear()
    portal.documentos.update({p: dict(d) for p, d in datos.DOCUMENTOS.items()})
    portal.sesiones._datos.clear()
    seg.reloj.desfase = timedelta(0)
    yield


def entrar(usuario, codigo=None):
    clave = datos.CUENTAS[usuario][2]
    cuerpo = {"usuario": usuario, "clave": clave}
    if datos.CUENTAS[usuario][0] == "administrador":
        cuerpo["codigo_mfa"] = codigo or seg.codigo_totp(datos.SECRETO_MFA_LAB)
    r = cliente.post("/sesion", json=cuerpo)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def ultimo_motivo():
    return REGISTRO.read_text(encoding="utf-8").strip().splitlines()[-1]


# ---------------------------------------------------------------- matriz RBAC completa (5 roles x 8 operaciones)
SOLICITUD = {
    "leer":           ("GET", "/proyectos/P01/documentos/resumen_P01.txt", None),
    "descargar":      ("GET", "/proyectos/P01/documentos/dataset_A.zip/descarga", None),
    "editar":         ("PUT", "/proyectos/P01/documentos/resultados.csv", {"contenido": "id,valor"}),
    "publicar":       ("POST", "/proyectos/P01/documentos/resumen_P01.txt/publicacion", None),
    "eliminar":       ("DELETE", "/proyectos/P01/documentos/resumen_P01.txt", None),
    "asignar_rol":    ("PUT", "/admin/usuarios/estudiante03/rol", {"rol": "estudiante"}),
    "revocar_acceso": ("POST", "/usuarios/externo01/revocacion", {"motivo": "prueba"}),
    "ver_registros":  ("GET", "/admin/registros", None),
}
# Resultado esperado escrito a mano (no se toma de datos.MATRIZ, para que la prueba sea independiente)
ESPERADO = {
    "estudiante03":   {"leer"},
    "externo01":      {"leer"},
    "investigador07": {"leer", "descargar", "editar"},
    "director01":     {"leer", "descargar", "editar", "publicar", "eliminar", "revocar_acceso"},
    "admin01":        {"asignar_rol", "revocar_acceso", "ver_registros"},
}


@pytest.mark.parametrize("usuario", list(ESPERADO))
@pytest.mark.parametrize("operacion", list(SOLICITUD))
def test_matriz_rbac(usuario, operacion):
    metodo, ruta, cuerpo = SOLICITUD[operacion]
    r = cliente.request(metodo, ruta, json=cuerpo, headers=entrar(usuario))
    esperado = 200 if operacion in ESPERADO[usuario] else 403
    assert r.status_code == esperado, f"{usuario} {operacion}: {r.status_code}"


# ---------------------------------------------------------------- acceso horizontal (usuario A sobre recursos de B)
@pytest.mark.parametrize("usuario,metodo,ruta", [
    ("investigador07", "GET", "/proyectos/P02/documentos/muestra_P02.csv"),
    ("investigador15", "GET", "/proyectos/P01/documentos/dataset_A.zip/descarga"),
    ("director02", "DELETE", "/proyectos/P01/documentos/resultados.csv"),
    ("externo01", "GET", "/proyectos/P02/documentos"),
    ("investigador07", "GET", "/proyectos/P02/documentos/no_existe.txt"),   # 403 y no 404: no revela que existe
])
def test_horizontal_proyecto_ajeno(usuario, metodo, ruta):
    r = cliente.request(metodo, ruta, headers=entrar(usuario))
    assert r.status_code == 403
    assert "no es del usuario" in ultimo_motivo()


def test_horizontal_director_no_revoca_miembros_de_otro_proyecto():
    r = cliente.post("/usuarios/investigador15/revocacion", json={}, headers=entrar("director01"))
    assert r.status_code == 403
    assert "solo revoca miembros de sus proyectos" in ultimo_motivo()


# ---------------------------------------------------------------- acceso vertical (funciones de un rol superior)
@pytest.mark.parametrize("usuario,metodo,ruta,cuerpo", [
    ("investigador07", "PUT", "/admin/usuarios/investigador07/rol", {"rol": "director"}),   # autoelevacion
    ("investigador07", "GET", "/admin/registros", None),
    ("director01", "PUT", "/admin/usuarios/investigador07/rol", {"rol": "director"}),
    ("externo01", "POST", "/proyectos/P01/documentos/resumen_P01.txt/publicacion", None),
    ("estudiante03", "GET", "/proyectos/P01/documentos/dataset_A.zip/descarga", None),
    ("admin01", "GET", "/proyectos/P01/documentos/resumen_P01.txt", None),                # minimo privilegio
])
def test_vertical_funcion_no_permitida(usuario, metodo, ruta, cuerpo):
    r = cliente.request(metodo, ruta, json=cuerpo, headers=entrar(usuario))
    assert r.status_code == 403
    assert "no permitida para el rol" in ultimo_motivo()


# ---------------------------------------------------------------- autenticacion y MFA
def test_clave_incorrecta():
    r = cliente.post("/sesion", json={"usuario": "investigador07", "clave": "adivinada"})
    assert r.status_code == 401 and "LOGIN_FAIL" in ultimo_motivo()


def test_administrador_sin_mfa_es_rechazado():
    r = cliente.post("/sesion", json={"usuario": "admin01", "clave": datos.CUENTAS["admin01"][2]})
    assert r.status_code == 401 and "segundo factor" in ultimo_motivo()


def test_administrador_con_mfa_incorrecto_es_rechazado():
    r = cliente.post("/sesion", json={"usuario": "admin01", "clave": datos.CUENTAS["admin01"][2],
                                      "codigo_mfa": "000000"})
    assert r.status_code == 401


def test_administrador_con_mfa_valido_entra():
    assert entrar("admin01")


def test_externo_con_convenio_vencido_no_entra():
    r = cliente.post("/sesion", json={"usuario": "externo02", "clave": datos.CUENTAS["externo02"][2]})
    assert r.status_code == 403 and "acceso vencido" in ultimo_motivo()


# ---------------------------------------------------------------- sesiones y tokens
def test_cookie_con_banderas_seguras():
    r = cliente.post("/sesion", json={"usuario": "investigador07", "clave": datos.CUENTAS["investigador07"][2]})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=strict" in cookie


def test_token_alterado_es_rechazado():
    cab = entrar("investigador07")
    cab["Authorization"] = cab["Authorization"][:-2] + "xx"
    assert cliente.get("/proyectos/P01/documentos", headers=cab).status_code == 401


def test_cierre_de_sesion_invalida_el_token():
    cab = entrar("investigador07")
    assert cliente.delete("/sesion", headers=cab).status_code == 200
    assert cliente.get("/proyectos/P01/documentos", headers=cab).status_code == 401


def test_expiracion_por_inactividad():
    cab = entrar("investigador07")
    seg.reloj.desfase = seg.INACTIVIDAD + timedelta(minutes=1)
    assert cliente.get("/proyectos/P01/documentos", headers=cab).status_code == 401
    assert "inactividad" in ultimo_motivo()


def test_expiracion_por_duracion_maxima_aunque_haya_actividad():
    cab = entrar("investigador07")
    paso = seg.INACTIVIDAD - timedelta(minutes=1)
    while seg.reloj.desfase <= seg.DURACION_MAXIMA:
        seg.reloj.desfase += paso
        r = cliente.get("/proyectos/P01/documentos", headers=cab)
    assert r.status_code == 401 and "duracion maxima" in ultimo_motivo()


def test_cambio_de_rol_aplica_a_la_sesion_ya_abierta():
    cab_inv = entrar("investigador07")
    assert cliente.put("/admin/usuarios/investigador07/rol", json={"rol": "estudiante"},
                       headers=entrar("admin01")).status_code == 200
    r = cliente.get("/proyectos/P01/documentos/dataset_A.zip/descarga", headers=cab_inv)
    assert r.status_code == 403


# ---------------------------------------------------------------- reto: fin del proyecto con sesion activa
def test_reto_revocacion_cierra_la_sesion_activa_del_externo():
    cab_ext = entrar("externo01")
    assert cliente.get("/proyectos/P01/documentos/resumen_P01.txt", headers=cab_ext).status_code == 200
    r = cliente.post("/usuarios/externo01/revocacion", json={"motivo": "fin del proyecto"},
                     headers=entrar("director01"))
    assert r.status_code == 200 and r.json()["sesiones_cerradas"] == 1
    assert cliente.get("/proyectos/P01/documentos/resumen_P01.txt", headers=cab_ext).status_code == 401
    r = cliente.post("/sesion", json={"usuario": "externo01", "clave": datos.CUENTAS["externo01"][2]})
    assert r.status_code == 403


def test_reto_vencimiento_sin_revocacion_se_detecta_en_cada_solicitud():
    cab_ext = entrar("externo01")
    portal.cuentas["externo01"]["acceso_hasta"] = seg.reloj.ahora() + timedelta(minutes=5)
    seg.reloj.desfase = timedelta(minutes=6)          # la sesion sigue viva (menos de 15 min de inactividad)
    r = cliente.get("/proyectos/P01/documentos/resumen_P01.txt", headers=cab_ext)
    assert r.status_code == 403 and "acceso vencido" in ultimo_motivo()


# ---------------------------------------------------------------- registros sin secretos
def test_registros_no_contienen_secretos():
    cab = entrar("investigador07")
    token = cab["Authorization"][7:]
    cliente.post("/sesion", json={"usuario": "investigador07", "clave": "Clave-Equivocada-123"})
    codigo = seg.codigo_totp(datos.SECRETO_MFA_LAB)
    entrar("admin01", codigo)
    texto = REGISTRO.read_text(encoding="utf-8")
    for secreto in [token, "Clave-Equivocada-123", codigo, datos.SECRETO_MFA_LAB] + \
                   [c[2] for c in datos.CUENTAS.values()]:
        assert secreto not in texto
    assert "denegado" in texto and "permitido" in texto
