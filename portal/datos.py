"""Datos ficticios del laboratorio: cuentas, proyectos, documentos y matriz RBAC.
Las contrasenas y el secreto MFA son de laboratorio; en un sistema real vivirian como hashes en una base de datos."""
from datetime import datetime, timedelta, timezone

BOGOTA = timezone(timedelta(hours=-5))

# ---------------------------------------------------------------- matriz RBAC
OPERACIONES = ["leer", "descargar", "editar", "publicar", "eliminar",
               "asignar_rol", "revocar_acceso", "ver_registros"]

# Operaciones permitidas por rol. Las de documentos solo valen dentro de los proyectos del usuario.
MATRIZ = {
    "estudiante":    {"leer"},
    "externo":       {"leer"},
    "investigador":  {"leer", "descargar", "editar"},
    "director":      {"leer", "descargar", "editar", "publicar", "eliminar", "revocar_acceso"},
    "administrador": {"asignar_rol", "revocar_acceso", "ver_registros"},
}
OPERACIONES_DE_PROYECTO = {"leer", "descargar", "editar", "publicar", "eliminar"}
ROLES_ALTO_IMPACTO = {"administrador"}          # exigen segundo factor (MFA)

# ---------------------------------------------------------------- cuentas ficticias
SECRETO_MFA_LAB = "JBSWY3DPEHPK3PXP"           # base32, solo laboratorio

CUENTAS = {
    # usuario: (rol, proyectos, contrasena de laboratorio, acceso_hasta)
    "estudiante03":   ("estudiante",    ["P01"], "Estudiante-03!", None),
    "investigador07": ("investigador",  ["P01"], "Investiga-07!", None),
    "investigador09": ("investigador",  ["P01"], "Investiga-09!", None),
    "investigador15": ("investigador",  ["P02"], "Investiga-15!", None),
    "director01":     ("director",      ["P01"], "Director-01!", None),
    "director02":     ("director",      ["P02"], "Director-02!", None),
    "externo01":      ("externo",       ["P01"], "Externo-01!", datetime(2027, 12, 31, 23, 59, tzinfo=BOGOTA)),
    "externo02":      ("externo",       ["P02"], "Externo-02!", datetime(2026, 10, 31, 23, 59, tzinfo=BOGOTA)),
    "admin01":        ("administrador", [],      "Admin-01!", None),
}

DOCUMENTOS = {
    "P01": {"resumen_P01.txt": ("Resumen ficticio del proyecto P01.", 0.1),
            "dataset_A.zip": ("<contenido ficticio de dataset_A>", 620),
            "resultados.csv": ("id,valor\nS001,0.42\n", 0.1)},
    "P02": {"muestra_P02.csv": ("id,valor\nM001,1.7\n", 0.1),
            "modelo_P02.bin": ("<contenido ficticio de modelo_P02>", 280)},
}
