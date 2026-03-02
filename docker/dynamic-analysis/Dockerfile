# Dynamic Analysis Container for Project Pegasus
# Uses Ubuntu base with manually installed analysis tools

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /analysis

# Install system dependencies and dynamic analysis tools
RUN apt-get update && apt-get install -y \
    # Core system packages
    python3 \
    python3-pip \
    # Monitoring and tracing tools
    strace \
    ltrace \
    tcpdump \
    lsof \
    procps \
    inotify-tools \
    # Network utilities
    iputils-ping \
    curl \
    wget \
    iproute2 \
    iptables \
    net-tools \
    # Cross-architecture emulation
    qemu-user \
    qemu-user-static \
    binfmt-support \
    # Cross-compilation libraries (32-bit support)
    libc6-i386 \
    lib32gcc-s1 \
    # Windows PE execution (Wine - best effort)
    wine \
    # Packers and compression
    upx \
    xz-utils \
    p7zip-full \
    # Scripting languages for malware analysis
    nodejs \
    npm \
    bash \
    perl \
    php-cli \
    ruby \
    # Utilities
    file \
    curl \
    wget \
    unzip \
    libcap2-bin \
    # Network utilities
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Allow tcpdump to run as non-root user (CRITICAL for network capture)
# Handle different tcpdump locations across distributions
RUN TCPDUMP_PATH=$(which tcpdump 2>/dev/null || echo "/usr/bin/tcpdump") && \
    if [ -f "$TCPDUMP_PATH" ] && [ ! -L "$TCPDUMP_PATH" ]; then \
        setcap cap_net_raw,cap_net_admin+eip "$TCPDUMP_PATH" || echo "Warning: Could not set tcpdump capabilities"; \
    else \
        echo "Note: tcpdump capabilities may need to be set at runtime"; \
    fi

# Try to install newer UPX release (fallback to apt version if download fails)
RUN set -eux; \
    UPX_VER=4.0.1; \
    ARCH=$(uname -m); \
    case "$ARCH" in \
        x86_64) UPX_ARCH="amd64" ;; \
        aarch64) UPX_ARCH="aarch64" ;; \
        *) UPX_ARCH="amd64" ;; \
    esac; \
    UPX_TAR=upx-${UPX_VER}-${UPX_ARCH}_linux.tar.xz; \
    UPX_URL=https://github.com/upx/upx/releases/download/v${UPX_VER}/${UPX_TAR}; \
    if curl -fsSL -o /tmp/${UPX_TAR} ${UPX_URL}; then \
        mkdir -p /tmp/upx && \
        tar -xJf /tmp/${UPX_TAR} -C /tmp/upx && \
        if [ -f /tmp/upx/*/upx ]; then \
            cp /tmp/upx/*/upx /usr/local/bin/upx && \
            chmod +x /usr/local/bin/upx; \
        fi && \
        rm -rf /tmp/upx /tmp/${UPX_TAR}; \
    fi || echo "UPX download failed, using system version"

# Register binfmt handlers for transparent cross-arch execution
# This allows execve() of foreign ELFs to automatically invoke QEMU
RUN update-binfmts --enable

# Install Python packages for monitoring
RUN pip3 install --no-cache-dir \
    psutil==5.9.5

WORKDIR /analysis

# Copy monitoring scripts
COPY monitor.py /analysis/monitor.py
COPY run_sample.sh /analysis/run_sample.sh

# Make scripts executable
RUN chmod +x /analysis/monitor.py /analysis/run_sample.sh

# Create workspace with proper permissions
RUN mkdir -p /analysis/workspace && chmod 1777 /analysis/workspace

# Create non-root user for execution
RUN useradd -m -s /bin/bash malware && \
    chown -R malware:malware /analysis/workspace && \
    chown malware:malware /analysis/monitor.py /analysis/run_sample.sh

# IMPORTANT: Switch to non-root user for security
USER malware

# Default command
CMD ["python3", "/analysis/monitor.py", "/analysis/sample"]
