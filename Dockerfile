# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    HOME=/app

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    dnsutils \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r sud0hunt && \
    useradd -r -g sud0hunt -d /app -s /bin/bash sud0hunt

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create reports directory and set permissions
RUN mkdir -p reports data && \
    chown -R sud0hunt:sud0hunt /app && \
    chmod +x cli.py

# Switch to non-root user
USER sud0hunt

# Expose port (if needed for future web interface)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python cli.py --version || exit 1

# Set default command
ENTRYPOINT ["python", "cli.py"]
CMD ["--help"]

# Metadata
LABEL org.opencontainers.image.title="Sud0Hunt" \
      org.opencontainers.image.description="Advanced Automated Bug Bounty Reconnaissance & Vulnerability Hunter" \
      org.opencontainers.image.url="https://github.com/Sud0-x/Sud0Hunt" \
      org.opencontainers.image.source="https://github.com/Sud0-x/Sud0Hunt" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.created="2025-01-02" \
      org.opencontainers.image.revision="main" \
      org.opencontainers.image.vendor="Sud0-x" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.author="sud0x.dev@proton.me"
