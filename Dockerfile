FROM node:22-bookworm-slim AS frontend
WORKDIR /app/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
WORKDIR /app
ENV HOST=0.0.0.0 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
# Railway supplies PORT and OpenAI configuration at runtime.
COPY *.py ./
COPY investigation/ ./investigation/
COPY fixtures/ ./fixtures/
COPY --from=frontend /app/web/dist ./web/dist
CMD ["python", "run_product.py"]
