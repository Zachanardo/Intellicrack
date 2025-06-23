# Dockerfile for Intellicrack
# Multi-stage build for optimal image size

# Build stage
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    git \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy requirements
COPY requirements/base.txt requirements/optional.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r base.txt && \
    pip install --no-cache-dir -r optional.txt || true

# Runtime stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    # GUI support
    libgl1-mesa-glx \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgomp1 \
    libglu1-mesa \
    # Network tools
    libpcap0.8 \  # Optional backend for Scapy packet capture
    tcpdump \
    # Binary tools
    file \
    binutils \
    # Other utilities
    git \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash intellicrack

# Set working directory
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=intellicrack:intellicrack . .

# Install Intellicrack
RUN pip install --no-cache-dir -e .

# Switch to non-root user
USER intellicrack

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV QT_QPA_PLATFORM=offscreen
ENV INTELLICRACK_CONFIG_PATH=/app/config/intellicrack_config.json

# Expose ports
EXPOSE 8080 9999

# Entry point
ENTRYPOINT ["python", "-m", "intellicrack"]

# Default command (can be overridden)
CMD ["--help"]