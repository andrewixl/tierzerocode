# Run this command to build the image
# docker build -t andrewixl/tierzerocode .

# Other Commands:
# sudo docker exec -it awb-ctr-tzc-ep1 sh
# python manage.py makemigrations
# python manage.py migrate
# python manage.py createsuperuser

# Stage 1: Base build stage
FROM python:alpine AS builder
 
# Create the app directory
RUN mkdir /app
 
# Set the working directory
WORKDIR /app
 
# Set environment variables to optimize Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1 
 
# Upgrade pip and install dependencies
RUN pip install --upgrade pip 
 
# Copy the requirements file first (better caching)
COPY requirements.txt /app/
 
# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
 
# Stage 2: Production stage
FROM python:alpine
 
RUN adduser -D -s /bin/sh appuser && \
   mkdir /app && \
   chown -R appuser /app
 
# Copy the Python dependencies from the builder stage
# Copy entire lib and bin directories, then organize by Python version
COPY --from=builder /usr/local/lib /tmp/builder-lib
COPY --from=builder /usr/local/bin /tmp/builder-bin
RUN SITE_PKG=$(python3 -c "import site; print(site.getsitepackages()[0])") && \
    mkdir -p $(dirname $SITE_PKG) && \
    cp -r /tmp/builder-lib/python*/site-packages/* $SITE_PKG/ && \
    cp -r /tmp/builder-bin/* /usr/local/bin/ && \
    rm -rf /tmp/builder-lib /tmp/builder-bin
 
# Set the working directory
WORKDIR /app
 
# Copy application code
COPY --chown=appuser:appuser . .

# Copy and make startup script executable
COPY --chown=appuser:appuser start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Create static directory and collect static files
RUN mkdir -p /app/static && \
    chown -R appuser:appuser /app/static && \
    python manage.py collectstatic --noinput || true

# Set environment variables to optimize Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1 

# Switch to non-root user
USER appuser
 
# Expose the application port
EXPOSE 8000 
 
# Start both gunicorn and rqworker using the startup script
CMD ["/app/start.sh"]
