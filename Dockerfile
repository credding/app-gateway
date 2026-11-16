FROM node:22-slim AS web
RUN corepack enable
WORKDIR /app

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml /app/
COPY packages/console-app-web/package.json /app/packages/console-app-web/
RUN pnpm install --frozen-lockfile

COPY packages/console-app-web /app/packages/console-app-web
RUN pnpm --filter console-app-web build

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

COPY --from=web /app/packages/console-app-web/build /app/packages/console-app-web/build

CMD ["/app/.venv/bin/fastapi", "run"]
