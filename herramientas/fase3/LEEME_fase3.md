# Fase 3 – Analizador de registros

## Instalación
Copie esta carpeta `fase3` dentro de `atenea-lab/herramientas/`, de modo que quede `atenea-lab/herramientas/fase3/analizador.py`.
No hay que reiniciar nada: la carpeta `herramientas` ya está conectada al contenedor auditor.

## Ejecutar todo (desde PowerShell, en la carpeta atenea-lab)
```
docker compose exec auditor sh /herramientas/fase3/correr_fase3.sh
```
Hace cuatro cosas: calcula el hash de los CSV, analiza los cinco casos, corre las pruebas automáticas y confirma que los CSV no cambiaron.
Los resultados quedan en `evidencias/fase3/`, una carpeta por caso con `reporte.txt`, `alertas.csv`, `linea_de_tiempo.csv` y `descartes.csv`.

## Analizar un solo archivo
```
docker compose exec auditor python3 /herramientas/fase3/analizador.py /herramientas/fase3/datos/muestra_enunciado.csv
```

## Parámetros
Los umbrales (5 fallos en 10 minutos, 500 MB, 30 minutos, horario laboral, zona horaria) están al inicio de `analizador.py`.
