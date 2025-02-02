FROM python:3.8.3 AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /app


RUN python -m venv .venv
COPY requirements.txt ./
RUN .venv/bin/pip install -r requirements.txt
FROM python:3.8.3-slim
WORKDIR /app
COPY --from=builder /app/.venv .venv/
COPY . .
CMD ["/app/.venv/bin/gunicorn", "-k", "eventlet", "-w", "1", "-b", "0.0.0.0:8080", "app:app"]
