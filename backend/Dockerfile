# Production image: multi-stage so build tooling (gcc, headers) never ships in the
# final layer, and dependencies are installed once into a venv that gets copied
# verbatim rather than re-resolved at runtime.

FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml constraints.txt ./
# Copy only what the build backend (hatchling) needs to resolve the package
# metadata before the rest of the source lands, so dependency installation is
# cached across source-only changes.
COPY app ./app
# Pinned to the versions the tests passed against (see constraints.txt).
RUN pip install --no-cache-dir -c constraints.txt .


FROM python:3.12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 appsec

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY --chown=appsec:appsec app ./app
COPY --chown=appsec:appsec alembic ./alembic
COPY --chown=appsec:appsec alembic.ini ./
COPY --chown=appsec:appsec docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && mkdir -p /app/uploads/pentest-reports /app/uploads/sbom-evidence \
    && chown -R appsec:appsec /app/uploads

USER appsec

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
