FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py datos.py seguridad.py ./
COPY tests ./tests
ENV REGISTRO_ACCESOS=/registros/accesos.csv
EXPOSE 80
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "80"]
