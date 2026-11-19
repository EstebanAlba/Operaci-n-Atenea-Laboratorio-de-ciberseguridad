# Laboratorio Operación Atenea – Fase 2

Laboratorio aislado con tres contenedores: portal (192.168.56.10), repositorio (192.168.56.11) y auditor (192.168.56.12).
Todos los datos son ficticios. La red es interna: ningún contenedor sale a internet ni a la red de la casa.

## Requisitos (Windows)
1. Docker Desktop instalado y abierto (usa WSL2).
2. PowerShell abierto en esta carpeta (`atenea-lab`).

## 1. Levantar el laboratorio
```
docker compose up -d --build
docker compose ps
```
Deben aparecer 4 contenedores en estado `running` (portal, repositorio, repositorio-ssh y auditor).

## 2. Escaneo inicial (antes del plan de cierre)
```
docker compose exec auditor sh /herramientas/escanear.sh --con-autenticacion
docker compose exec auditor python3 /herramientas/hallazgos.py /evidencias/antes/02_servicios.xml /evidencias/antes/04_detalle_servicios.xml /evidencias/antes/05_ssh_autenticacion.xml
```
Las evidencias quedan en `evidencias/antes/` (texto, XML, bitácora, hashes y hallazgos.csv).

## 3. Aplicar el plan de cierre
```
docker compose -f docker-compose.yml -f docker-compose.cierre.yml up -d
```

## 4. Escaneo de verificación (después del cierre)
```
docker compose exec -e ETAPA=despues auditor sh /herramientas/escanear.sh --con-autenticacion
docker compose exec auditor python3 /herramientas/hallazgos.py /evidencias/despues/02_servicios.xml /evidencias/despues/04_detalle_servicios.xml /evidencias/despues/05_ssh_autenticacion.xml
docker compose exec auditor ssh -o BatchMode=yes -o StrictHostKeyChecking=no admin_repo@192.168.56.11
```
El último comando debe responder `Permission denied (publickey)`: el auditor ya no puede entrar por SSH.

## 5. Ordenamiento externo (1.000.000 de filas)
```
docker compose exec auditor sh -c "cd /tmp && python3 /herramientas/ordenamiento_externo.py generar filas.csv 1000000 && python3 /herramientas/ordenamiento_externo.py memoria filas.csv mem.csv && python3 /herramientas/ordenamiento_externo.py externo filas.csv ext.csv 50000 && python3 /herramientas/ordenamiento_externo.py verificar mem.csv ext.csv"
```

## 6. Verificar la integridad de las evidencias
```
docker compose exec auditor sh -c "cd /evidencias/antes && sha256sum -c hashes_sha256.txt"
```

## Volver a la configuración inicial o apagar
```
docker compose up -d            # configuración inicial
docker compose down             # apaga y borra los contenedores (las evidencias se conservan)
```

## Si algo falla
- `Pool overlaps with other one on this address space`: otra red usa 192.168.56.0/24 (por ejemplo VirtualBox). Cambie la subred en `docker-compose.yml` y en los scripts de `herramientas/`.
- Errores `^M` o `not found` al ejecutar `escanear.sh`: el archivo quedó con finales de línea de Windows. Guárdelo con finales LF.
