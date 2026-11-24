# Operación Atenea – Laboratorio de ciberseguridad

Código y evidencias de las fases 2 a 7 del trabajo "Operación Atenea" (Ciberseguridad, Universidad Central).
El análisis completo está en el informe técnico; este repositorio permite reproducir cada prueba.

| Fase | Qué contiene | Dónde |
|---|---|---|
| 2. Auditoría ética, fingerprinting y scanning | Laboratorio aislado, escaneos con Nmap, tabla de hallazgos, plan de cierre y ordenamiento externo | `docker-compose.yml`, `docker-compose.cierre.yml`, `repositorio/`, `repositorio-ssh/`, `herramientas/` |
| 3. Investigación de accesos y anomalías | Analizador de registros en Python con 3 reglas, nivel de confianza y 5 casos de prueba | `herramientas/fase3/` |
| 4. Seguridad de identidades y aplicaciones | Portal en FastAPI con matriz RBAC, sesiones, MFA, registro sin secretos, 66 pruebas y demostración en vivo | `portal/`, `herramientas/fase4/` |
| 5. Criptografía y trazabilidad documental | Cifrado AES-256-GCM con clave envuelta, SHA-256, firmas Ed25519, mini CA ficticia, verificación de paquetes y 21 pruebas | `herramientas/fase5/` |
| 6. Riesgos, malware y controles de detección | Registros simulados con escenarios etiquetados, reglas de descargas anómalas, modificaciones masivas y señales de malware, calibración y 17 pruebas | `herramientas/fase6/` |
| 7. Normatividad y gobierno | Matriz de cumplimiento verificada contra las evidencias de las fases 2 a 6, matriz RACI de COBIT 5, evaluador de solicitudes de acceso y 18 pruebas | `herramientas/fase7/` |
| Evidencias | Salidas de cada ejecución con sus hashes SHA-256 | `evidencias/antes`, `evidencias/despues`, `evidencias/fase3` a `evidencias/fase7` |

Todos los datos, cuentas y contraseñas son ficticios y solo existen dentro del laboratorio.

## Requisitos
- Docker Desktop (en Windows, con WSL2) abierto.
- Una terminal (PowerShell o la de VS Code) ubicada en la carpeta del repositorio.

## Arquitectura
Tres contenedores en una red interna (`192.168.56.0/24`) sin salida a internet ni a la red local:

| Contenedor | Dirección | Servicios |
|---|---|---|
| atenea-portal | 192.168.56.10 | Portal de colaboración (FastAPI, puerto 80) |
| atenea-repositorio / atenea-repositorio-ssh | 192.168.56.11 | Repositorio web (nginx 1.24.0, puerto 80) y SSH de administración (puerto 22) |
| atenea-auditor | 192.168.56.12 | Nmap, Python y los scripts de `herramientas/` |

## Levantar el laboratorio
```
docker compose up -d --build
docker compose ps
```
Deben aparecer 4 contenedores en ejecución: atenea-portal, atenea-repositorio, atenea-repositorio-ssh y atenea-auditor.

---

## Fase 2 – Escaneo y plan de cierre
```
docker compose exec auditor sh /herramientas/escanear.sh --con-autenticacion
docker compose exec auditor python3 /herramientas/hallazgos.py /evidencias/antes/02_servicios.xml /evidencias/antes/04_detalle_servicios.xml /evidencias/antes/05_ssh_autenticacion.xml
docker compose -f docker-compose.yml -f docker-compose.cierre.yml up -d
docker compose exec -e ETAPA=despues auditor sh /herramientas/escanear.sh --con-autenticacion
docker compose exec auditor python3 /herramientas/hallazgos.py /evidencias/despues/02_servicios.xml /evidencias/despues/04_detalle_servicios.xml /evidencias/despues/05_ssh_autenticacion.xml
docker compose exec auditor ssh -o BatchMode=yes -o StrictHostKeyChecking=no admin_repo@192.168.56.11
```
Ordenamiento externo:
```
docker compose exec auditor sh -c "cd /tmp && python3 /herramientas/ordenamiento_externo.py generar filas.csv 1000000 && python3 /herramientas/ordenamiento_externo.py memoria filas.csv mem.csv && python3 /herramientas/ordenamiento_externo.py externo filas.csv ext.csv 50000 && python3 /herramientas/ordenamiento_externo.py verificar mem.csv ext.csv"
```
Evidencias en `evidencias/antes/` y `evidencias/despues/`.

## Fase 3 – Analizador de registros
```
docker compose exec auditor sh /herramientas/fase3/correr_fase3.sh
```
Evidencias en `evidencias/fase3/`.

## Fase 4 – Portal con roles, sesiones y MFA
Batería de pruebas (dentro del portal):
```
docker compose exec portal sh -c "pytest -v tests > /registros/pruebas_pytest.txt; tail -3 /registros/pruebas_pytest.txt"
```
Demostración en vivo desde el auditor:
```
docker compose exec auditor sh /herramientas/fase4/correr_fase4.sh
```
Para repetir la demostración, reinicie antes el portal (`docker compose restart portal`), porque revoca a externo01.
Evidencias en `evidencias/fase4/`.

### Cuentas ficticias del portal
| Usuario | Rol | Proyecto | Contraseña |
|---|---|---|---|
| estudiante03 | estudiante | P01 | Estudiante-03! |
| investigador07 | investigador | P01 | Investiga-07! |
| investigador09 | investigador | P01 | Investiga-09! |
| investigador15 | investigador | P02 | Investiga-15! |
| director01 | director | P01 | Director-01! |
| director02 | director | P02 | Director-02! |
| externo01 | externo | P01 (hasta 31/12/2027) | Externo-01! |
| externo02 | externo | P02 (venció 31/10/2026) | Externo-02! |
| admin01 | administrador | – (requiere MFA) | Admin-01! |

## Fase 5 – Criptografía y trazabilidad documental
```
docker compose exec auditor sh /herramientas/fase5/correr_fase5.sh
```
Cifrado, hash, firma, certificados, rotación de claves, 21 pruebas y verificación independiente del paquete firmado.
Evidencias en `evidencias/fase5/`. Verificación manual de un paquete:
```
docker compose exec auditor python3 /herramientas/fase5/fase5.py verificar /evidencias/fase5/paquete_firmado --esperado director01@atenea.test
```

## Fase 6 – Riesgos, malware y controles de detección
```
docker compose exec auditor sh /herramientas/fase6/correr_fase6.sh
```
Genera los registros simulados (semilla fija, siempre el mismo archivo), aplica las reglas de detección, evalúa cada escenario,
compara el umbral fijo con la línea base calibrada y corre 17 pruebas. Evidencias en `evidencias/fase6/`.

## Fase 7 – Normatividad y gobierno
```
docker compose exec auditor sh /herramientas/fase7/correr_fase7.sh
```
Comprueba que cada obligación de la matriz de cumplimiento esté respaldada por una evidencia que existe, conserva su hash
y muestra el resultado esperado; valida la matriz RACI de COBIT 5 y evalúa dos solicitudes de acceso (el reto).
Debe ejecutarse después de las fases 2 a 6, porque verifica sus evidencias. Resultados en `evidencias/fase7/`.

Evaluar otra solicitud de acceso:
```
docker compose exec auditor python3 /herramientas/fase7/solicitud_acceso.py /herramientas/fase7/datos/solicitud_justificada.json
```

---

## Volver a la configuración inicial, detener o apagar
```
docker compose up -d       # configuración inicial (deshace el plan de cierre)
docker compose stop        # detiene sin borrar; se reanuda con docker compose start
docker compose down        # borra los contenedores; las evidencias se conservan
```

## Si algo falla
- `Pool overlaps with other one on this address space`: otra red usa 192.168.56.0/24 (por ejemplo VirtualBox). Cambie la subred en `docker-compose.yml` y en los scripts de `herramientas/`.
- `Conflict. The container name "/atenea-..." is already in use`: hay otra copia del laboratorio encendida. Apáguela desde su carpeta con `docker compose down`.
- Errores `^M` o `not found` al ejecutar un `.sh`: el archivo quedó con finales de línea de Windows. Guárdelo con finales LF.
