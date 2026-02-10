# Stage 1: Build dependencies
FROM hub.awbtech.org/library/python:3-alpine3.23-dev AS builder

WORKDIR /app

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install build dependencies
RUN apk add --no-cache gcc musl-dev libffi-dev

# Upgrade pip and build wheels
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt


# Stage 2: Production image
FROM hub.awbtech.org/library/python:3-alpine3.23-dev

# Create user and directories in one layer to keep image size down
RUN adduser -D -s /bin/sh appuser && \
    mkdir -p /app/static && \
    chown -R appuser:appuser /app

WORKDIR /app

# Set production environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/appuser/.local/bin:${PATH}"

# Copy wheels and install
COPY --from=builder /app/wheels /tmp/wheels
RUN pip install --no-cache --user /tmp/wheels/* && \
    rm -rf /tmp/wheels

# Copy application code
COPY --chown=appuser:appuser . .

# Ensure start script is executable
RUN chmod +x /app/start.sh

# Collect static files
# Use the --no-input and ensure it doesn't crash the build if settings aren't fully loaded
RUN python manage.py collectstatic --noinput || true

# Security: Switch to non-root user
USER appuser

EXPOSE 8000

CMD ["/app/start.sh"]