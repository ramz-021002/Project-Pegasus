# Dynamic Analysis Container for Project Pegasus
# Platform-aware: REMnux for AMD64, Ubuntu for ARM64

# ============================================
# AMD64 base stage - REMnux (full tooling)
# ============================================
FROM --platform=linux/amd64 remnux/remnux-distro:focal AS base-amd64

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /analysis


# Install monitoring and analysis tools
RUN apt-get update && apt-get install -y \
    strace \
    ltrace \
    tcpdump \
    lsof \
    procps \
    inotify-tools \
    wine64 \
    wine32 \
    qemu-user \
    qemu-user-static \
    binfmt-support \
    upx \
    xz-utils \
    curl \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Allow tcpdump to run as non-root user
# This is CRITICAL for network capture in rootless container
RUN setcap cap_net_raw,cap_net_admin+eip /usr/sbin/tcpdump

# Try to install a newer UPX release (fallback to apt-installed `upx` if download fails)
RUN set -eux; \
    UPX_VER=4.0.1; \
    UPX_TAR=upx-${UPX_VER}-amd64_linux.tar.xz; \
    UPX_URL=https://github.com/upx/upx/releases/download/v${UPX_VER}/${UPX_TAR}; \
    if curl -fsSL -o /tmp/${UPX_TAR} ${UPX_URL}; then \
    mkdir -p /tmp/upx; tar -xJf /tmp/${UPX_TAR} -C /tmp/upx; \
    if [ -f /tmp/upx/*/upx ]; then cp /tmp/upx/*/upx /usr/local/bin/upx && chmod +x /usr/local/bin/upx; fi; \
    fi || true

# Install Node.js (LTS) and npm using NodeSource (works on REMnux/Ubuntu)
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && \
    apt-get update && apt-get install -y nodejs && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install --no-cache-dir \
    psutil==5.9.5

# ============================================
# ARM64 base stage - Ubuntu (manual setup)
# ============================================
FROM --platform=linux/arm64 ubuntu:20.04 AS base-arm64

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /analysis

# Install system dependencies for ARM64
# Includes QEMU user-mode emulation for running x86/MIPS/PPC malware on ARM
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    strace \
    ltrace \
    tcpdump \
    lsof \
    procps \
    inotify-tools \
    qemu-user \
    qemu-user-static \
    binfmt-support \
    xz-utils \
    libc6-i386-cross \
    libc6-amd64-cross \
    libc6-armhf-cross \
    libc6-mips-cross \
    libc6-mips64-cross \
    libc6-powerpc-cross \
    nodejs \
    npm \
    bash \
    perl \
    php-cli \
    ruby \
    file \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Allow tcpdump to run as non-root user (ARM64)
RUN setcap cap_net_raw,cap_net_admin+eip /usr/sbin/tcpdump

# Register binfmt handlers for transparent cross-arch execution
# This allows execve() of foreign ELFs to automatically invoke QEMU
RUN for arch in \
    qemu-x86_64:x86_64:x86-64 \
    qemu-i386:i386:Intel \
    qemu-arm:arm:ARM \
    qemu-mips:mips:MIPS \
    qemu-ppc:ppc:PowerPC \
    ; do \
    bin=$(echo $arch | cut -d: -f1); \
    if [ -f /usr/bin/${bin}-static ]; then \
    echo "Registered ${bin}-static for cross-arch emulation"; \
    fi; \
    done

# Install Python packages
RUN pip3 install --no-cache-dir \
    psutil==5.9.5

# Attempt to install newer UPX for ARM64 variant as well
RUN set -eux; \
    UPX_VER=4.0.1; \
    UPX_TAR=upx-${UPX_VER}-aarch64_linux.tar.xz; \
    UPX_URL=https://github.com/upx/upx/releases/download/v${UPX_VER}/${UPX_TAR}; \
    if curl -fsSL -o /tmp/${UPX_TAR} ${UPX_URL}; then \
    mkdir -p /tmp/upx; tar -xJf /tmp/${UPX_TAR} -C /tmp/upx; \
    if [ -f /tmp/upx/*/upx ]; then cp /tmp/upx/*/upx /usr/local/bin/upx && chmod +x /usr/local/bin/upx; fi; \
    fi || true

# ============================================
# Final stage - select based on TARGETARCH
# ============================================
ARG TARGETARCH
FROM base-${TARGETARCH} AS final

WORKDIR /analysis

# Force cache invalidation
RUN echo "Cache invalidation: debug-v2"

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
