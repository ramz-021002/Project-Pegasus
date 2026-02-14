# Static Analysis Container for Project Pegasus
# Platform-aware: REMnux for AMD64, Ubuntu for ARM64

# ============================================
# AMD64 base stage - REMnux (full tooling)
# ============================================
FROM --platform=linux/amd64 remnux/remnux-distro:focal AS base-amd64

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /analysis

# REMnux already has most tools; add any missing dependencies
RUN apt-get update && apt-get install -y \
    libfuzzy-dev \
    libmagic1 \
    xorsearch \
    && rm -rf /var/lib/apt/lists/*

# Install additional Python packages (--ignore-installed needed for distutils packages in REMnux)
RUN pip3 install --no-cache-dir --ignore-installed \
    pefile==2023.2.7 \
    python-magic==0.4.27 \
    yara-python==4.3.1 \
    ssdeep==3.4 \
    flare-capa==7.0.1

# ============================================
# ARM64 base stage - Ubuntu (manual setup)
# ============================================
FROM --platform=linux/arm64 ubuntu:20.04 AS base-arm64

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /analysis

# Install system dependencies for ARM64
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libssl-dev \
    libmagic1 \
    libfuzzy-dev \
    libfuzzy2 \
    ssdeep \
    xorsearch \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages for malware analysis
RUN pip3 install --no-cache-dir \
    pefile==2023.2.7 \
    python-magic==0.4.27 \
    yara-python==4.3.1 \
    ssdeep==3.4 \
    flare-capa==7.0.1

# ============================================
# Final stage - select based on TARGETARCH
# ============================================
ARG TARGETARCH
FROM base-${TARGETARCH} AS final

# Set working directory
WORKDIR /analysis

# Download CAPA rules and signatures
RUN apt-get update && apt-get install -y curl unzip && \
    mkdir -p /analysis/capa-rules /analysis/capa-signatures && \
    # Rules
    curl -sL https://github.com/mandiant/capa-rules/archive/refs/tags/v7.0.1.zip -o /tmp/capa-rules.zip && \
    unzip -q /tmp/capa-rules.zip -d /tmp && \
    mv /tmp/capa-rules-7.0.1/* /analysis/capa-rules/ && \
    # Signatures (from the main capa repo)
    curl -sL https://github.com/mandiant/capa/archive/refs/heads/master.zip -o /tmp/capa.zip && \
    unzip -q /tmp/capa.zip -d /tmp && \
    mv /tmp/capa-master/sigs/* /analysis/capa-signatures/ && \
    # Install Didier Stevens Suite (brxor, bbcrack, etc.)
    curl -sL https://github.com/DidierStevens/DidierStevensSuite/archive/master.zip -o /tmp/suite.zip && \
    unzip -q /tmp/suite.zip -d /tmp && \
    mkdir -p /opt/didier-suite && \
    cp /tmp/DidierStevensSuite-master/*.py /opt/didier-suite/ && \
    chmod +x /opt/didier-suite/*.py && \
    ln -sf /opt/didier-suite/brxor.py /usr/local/bin/brxor.py && \
    ln -sf /opt/didier-suite/bbcrack.py /usr/local/bin/bbcrack.py && \
    rm -rf /tmp/*.zip /tmp/capa-rules-7.0.1 /tmp/capa-master /tmp/DidierStevensSuite-master && \
    apt-get remove -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Copy analysis script
COPY analyze.py /analysis/analyze.py

# Make script executable
RUN chmod +x /analysis/analyze.py

# Create directories
RUN mkdir -p /analysis/workspace && chmod 1777 /analysis/workspace

# Run as non-root user
RUN useradd -m -s /bin/bash analyst && \
    chown -R analyst:analyst /analysis

# Switch to non-root user
USER analyst

# Default command
CMD ["python3", "/analysis/analyze.py", "/analysis/sample"]
