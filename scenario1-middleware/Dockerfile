# syntax=docker/dockerfile:1
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app/src:/app/simulators"

WORKDIR /build

COPY requirements.txt /build/requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r /build/requirements.txt


FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app/src:/app/simulators"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 appgroup \
    && useradd --uid 10001 --gid appgroup --shell /bin/false --create-home appuser

COPY --from=builder /install /usr/local
COPY --chown=appuser:appgroup . /app

RUN mkdir -p /app/state && chown -R appuser:appgroup /app/state

USER appuser

EXPOSE 8000

CMD ["uvicorn", "ingestor:app", "--app-dir", "src", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
