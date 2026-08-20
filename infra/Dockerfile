# syntax=docker/dockerfile:1.7

FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Keep the runtime image non-root.  No source or build secret is copied into
# the image; all credentials are supplied by the deployment secret manager.
RUN groupadd --system --gid 10001 platform \
    && useradd --system --uid 10001 --gid platform --create-home platform \
    && mkdir -p /app/platform \
    && chown -R platform:platform /app

COPY platform/requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm -f /tmp/requirements.txt

COPY --chown=platform:platform platform /app/platform
COPY --chown=platform:platform infra /app/infra
COPY --chown=platform:platform alembic.ini /app/alembic.ini

USER platform

EXPOSE 8000

ENTRYPOINT ["python", "-m"]
CMD ["uvicorn", "platform.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
