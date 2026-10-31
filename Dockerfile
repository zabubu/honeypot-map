FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Utilisateur sans privilèges ; /data reçoit la base SQLite (volume Docker)
RUN useradd --create-home app && mkdir /data && chown app:app /data

COPY api ./api
COPY ingester ./ingester
COPY web ./web

USER app
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
