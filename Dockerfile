FROM python:3.15-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

VOLUME ["/settings", "/data"]

ENV SETTINGS_DIR=/settings \
    DATA_DIR=/data

WORKDIR /app

COPY pyproject.toml uv.lock /app/
RUN uv sync --no-dev --locked --no-cache --no-install-project

COPY . /app
RUN uv sync --no-dev --locked --no-cache --no-editable

CMD ["/app/.venv/bin/fastapi", "run"]
