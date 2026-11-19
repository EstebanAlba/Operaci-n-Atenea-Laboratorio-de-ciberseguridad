# Fase 4 – Portal con roles, sesiones y MFA

## 1. Instalar la actualización
Copie el contenido de esta carpeta `atenea-lab` encima de su carpeta `atenea-lab` y acepte reemplazar los archivos.
Cambian: `docker-compose.yml`, la carpeta `portal/`, `herramientas/fase3/analizador.py` y se agrega `herramientas/fase4/`.

## 2. Reconstruir solo el portal (desde PowerShell, en atenea-lab)
```
docker compose up -d --build portal
```
Los demás contenedores no se tocan.

## 3. Batería de pruebas (66 pruebas, dentro del portal)
```
docker compose exec portal sh -c "pytest -v tests > /registros/pruebas_pytest.txt; tail -3 /registros/pruebas_pytest.txt"
```
El detalle de cada prueba queda en `evidencias/fase4/pruebas_pytest.txt`.

## 4. Demostración en vivo desde el auditor
```
docker compose exec auditor sh /herramientas/fase4/correr_fase4.sh
```
Ataca el portal real por la red del laboratorio, busca secretos en el registro y pasa el registro por el analizador de la fase 3.
Para repetirla, reinicie antes el portal: `docker compose restart portal` (la demostración revoca a externo01).

## Cuentas ficticias
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
