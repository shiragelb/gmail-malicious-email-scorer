FROM python:3.12-slim

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && rm -rf /root/.cache/pip

COPY backend /srv/backend
WORKDIR /srv/backend

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ENABLE_WHOIS=false \
    ENABLE_LIVE_DNS=false \
    USE_TRANSFORMERS=false \
    DEV_MODE=false \
    LOG_LEVEL=WARNING

USER appuser
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
