# Argus exporter image.
FROM python:3.11-slim

# Don't write .pyc files; stream logs straight to stdout (good for
# containers / Prometheus log scraping).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first so Docker can cache this layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code and the example config (used as a fallback if
# no config.yaml is mounted in).
COPY argus/ ./argus/
COPY config.example.yaml ./config.yaml

# Run as a non-root user.
RUN useradd --create-home --uid 10001 argus
USER argus

EXPOSE 9882

# The exporter serves /metrics on :9882. Override --config to point at a
# mounted config file (see deploy/docker-compose.yml).
ENTRYPOINT ["python", "-m", "argus.exporter"]
CMD ["--config", "config.yaml"]
