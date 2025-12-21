# Stage 1: Build dependencies
FROM python:3.11-slim AS builder
WORKDIR /app

COPY requirements/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -t /deps

# Stage 2: Minimal runtime
FROM python:3.11-alpine
WORKDIR /app

ENV APP_ENV=production
ENV APP_VERSION=1.0

COPY --from=builder /deps /usr/local/lib/python3.11/site-packages
COPY src/app.py .

ENTRYPOINT ["python", "app.py"]
CMD []

