FROM python:3.12-slim AS exporter

RUN pip install --no-cache-dir \
        torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir "transformers>=4.44,<5" "onnx>=1.16,<2" \
    && rm -rf /root/.cache/pip /root/.cache/huggingface

WORKDIR /export
COPY backend/scripts/export_onnx_classifier.py .
ARG ONNX_EXPORT_MODEL=aamoshdahal/email-phishing-distilbert-finetuned
ENV ONNX_EXPORT_MODEL=${ONNX_EXPORT_MODEL} \
    HF_HUB_DISABLE_TELEMETRY=1
RUN python export_onnx_classifier.py --out /models \
    && rm -rf /root/.cache/huggingface /root/.cache/pip

FROM python:3.12-slim

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && rm -rf /root/.cache/pip

COPY backend /srv/backend
COPY --from=exporter /models /srv/backend/models/phishing-onnx
WORKDIR /srv/backend

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ENABLE_WHOIS=false \
    ENABLE_LIVE_DNS=false \
    ENABLE_DOMAIN_AGE=false \
    USE_TRANSFORMERS=false \
    USE_ONNX_CLASSIFIER=true \
    ONNX_MODEL_DIR=/srv/backend/models/phishing-onnx \
    ENABLE_DEEP_SCAN=false \
    BUDGET_USD_PER_DAY=1 \
    DEV_MODE=false \
    LOG_LEVEL=WARNING

USER appuser
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
