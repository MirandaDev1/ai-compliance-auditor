FROM python:3.11-slim AS builder
WORKDIR /build_staging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends build-essential gcc && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir --upgrade pip
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /build_staging/wheels -r requirements.txt
FROM python:3.11-slim AS runner
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DLP_SCAN_DIR=/app/compliance_vault
ENV DLP_METRICS_PORT=8000
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build_staging/wheels /wheels
COPY --from=builder /build_staging/requirements.txt .
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt && rm -rf /wheels
COPY main.py .
RUN mkdir -p /app/compliance_vault /app/logs && useradd -u 10001 dlp_auditor && chown -R dlp_auditor:dlp_auditor /app
USER dlp_auditor
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD curl -f http://localhost:8000/metrics || exit 1
ENTRYPOINT ["python", "main.py"]
