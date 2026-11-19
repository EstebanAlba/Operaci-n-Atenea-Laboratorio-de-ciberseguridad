"""Ordenamiento externo de hallazgos: ordena archivos CSV que no caben en memoria.

Idea: 1) leer el archivo por bloques de N filas, ordenar cada bloque en memoria y guardarlo en un archivo temporal;
      2) mezclar los bloques ya ordenados leyendo una fila a la vez de cada uno (heapq.merge).
La memoria usada depende del tamano del bloque, no del tamano total del archivo.

Uso:
  python3 ordenamiento_externo.py generar  filas.csv 1000000     # crea hallazgos sinteticos
  python3 ordenamiento_externo.py externo  filas.csv salida.csv 50000
  python3 ordenamiento_externo.py memoria  filas.csv salida.csv  # ordenamiento normal, para comparar
  python3 ordenamiento_externo.py verificar a.csv b.csv          # confirma que dos salidas son identicas
"""
import csv
import hashlib
import heapq
import os
import random
import sys
import tempfile
import time
import tracemalloc

CAMPOS = ["activo", "ip", "puerto", "prioridad", "hallazgo"]
PRIORIDAD = {"Alta": 0, "Media": 1, "Baja": 2, "Informativa": 3}


def clave(fila):
    return (fila[0], int(fila[2]), PRIORIDAD[fila[3]])


def generar(destino, n):
    random.seed(42)
    activos = ["REPO-01", "PORTAL-01", "DATA-01", "AUTH-01", "BACKUP-01", "MON-01"]
    with open(destino, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(CAMPOS)
        for i in range(n):
            w.writerow([random.choice(activos), f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
                        random.choice([22, 80, 443, 3306, 8080, 9200]), random.choice(list(PRIORIDAD)), f"hallazgo-{i}"])


def externo(origen, destino, tam_bloque):
    temporales = []
    with open(origen, newline="") as fh:
        r = csv.reader(fh)
        encabezado = next(r)
        while True:
            bloque = [f for _, f in zip(range(tam_bloque), r)]
            if not bloque:
                break
            bloque.sort(key=clave)
            t = tempfile.NamedTemporaryFile("w", delete=False, newline="", suffix=".csv")
            csv.writer(t).writerows(bloque)
            t.close()
            temporales.append(t.name)
    lectores = [open(t, newline="") for t in temporales]
    with open(destino, "w", newline="") as out:
        w = csv.writer(out)
        w.writerow(encabezado)
        w.writerows(heapq.merge(*(csv.reader(l) for l in lectores), key=clave))
    for l, t in zip(lectores, temporales):
        l.close()
        os.remove(t)
    return len(temporales)


def memoria(origen, destino):
    with open(origen, newline="") as fh:
        r = csv.reader(fh)
        encabezado = next(r)
        filas = sorted(r, key=clave)
    with open(destino, "w", newline="") as out:
        w = csv.writer(out)
        w.writerow(encabezado)
        w.writerows(filas)


def sha256(ruta):
    h = hashlib.sha256()
    with open(ruta, "rb") as fh:
        for trozo in iter(lambda: fh.read(1 << 20), b""):
            h.update(trozo)
    return h.hexdigest()


def medir(funcion, *args):
    tracemalloc.start()
    t0 = time.perf_counter()
    resultado = funcion(*args)
    seg = time.perf_counter() - t0
    pico = tracemalloc.get_traced_memory()[1] / 2**20
    tracemalloc.stop()
    return resultado, seg, pico


if __name__ == "__main__":
    modo = sys.argv[1] if len(sys.argv) > 1 else ""
    if modo == "generar":
        generar(sys.argv[2], int(sys.argv[3]))
        print(f"Generadas {sys.argv[3]} filas en {sys.argv[2]}")
    elif modo == "externo":
        bloques, seg, pico = medir(externo, sys.argv[2], sys.argv[3], int(sys.argv[4]))
        print(f"Externo: {bloques} bloques de {sys.argv[4]} filas, {seg:.1f} s, pico de memoria {pico:.1f} MB")
    elif modo == "memoria":
        _, seg, pico = medir(memoria, sys.argv[2], sys.argv[3])
        print(f"En memoria: {seg:.1f} s, pico de memoria {pico:.1f} MB")
    elif modo == "verificar":
        a, b = sha256(sys.argv[2]), sha256(sys.argv[3])
        print(f"SHA-256 {a[:16]}... vs {b[:16]}... -> {'IDENTICOS' if a == b else 'DIFERENTES'}")
    else:
        sys.exit(__doc__)
