FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN CODEGUARD_DOCKER_BUILD=1 npm run build
FROM python:3.12-slim
WORKDIR /srv/codeguard
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
COPY --from=frontend /build/dist ./web
RUN useradd --create-home codeguard && mkdir /data && chown -R codeguard:codeguard /data /srv/codeguard
USER codeguard
ENV CODEGUARD_HOST=0.0.0.0 PORT=8000 CODEGUARD_DB_PATH=/data/codeguard.db CODEGUARD_ENABLE_DOCS=0
EXPOSE 8000
CMD ["python", "main.py"]
