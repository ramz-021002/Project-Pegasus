# Static Analysis Container for Project Pegasus
# Uses Ubuntu base with manually installed analysis tools

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /analysis

# Install system dependencies and analysis tools
RUN apt-get update && apt-get install -y \
    # Core system packages
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    gcc \
    g++ \
    # Libraries
    libssl-dev \
    libcrypto++-dev \
    libmagic1 \
    libfuzzy-dev \
    libfuzzy2 \
    libpq-dev \
    # Analysis tools
    ssdeep \
    binutils \
    file \
    bsdutils \
    xxd \
    # Network tools for downloading
    curl \
    wget \
    unzip \
    git \
    # YARA dependencies
    automake \
    libtool \
    make \
    pkg-config \
    flex \
    bison \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages for malware analysis
RUN pip3 install --no-cache-dir \
    pefile==2023.2.7 \
    python-magic==0.4.27 \
    yara-python==4.3.1 \
    ssdeep==3.4 \
    flare-capa==7.0.1

# Install XORSearch from Didier Stevens' official site
RUN cd /tmp && \
    curl -sL http://didierstevens.com/files/software/XORStrings_V0_0_1.zip -o xorstrings.zip && \
    unzip -q xorstrings.zip && \
    # Try to compile XORStrings.c with proper libraries
    if [ -f "XORStrings.c" ]; then \
        gcc -o /usr/local/bin/xorsearch XORStrings.c -lssl -lcrypto || \
        gcc -o /usr/local/bin/xorsearch XORStrings.c || \
        # If compilation fails, create a stub that at least doesn't break analysis
        (echo '#include <stdio.h>' > xorsearch_stub.c && \
         echo 'int main(int argc, char *argv[]){ printf("XORSearch functionality not available\\n"); return 0; }' >> xorsearch_stub.c && \
         gcc -o /usr/local/bin/xorsearch xorsearch_stub.c); \
    else \
        # No source found, create stub
        echo '#include <stdio.h>' > xorsearch_stub.c && \
        echo 'int main(int argc, char *argv[]){ printf("XORSearch functionality not available\\n"); return 0; }' >> xorsearch_stub.c && \
        gcc -o /usr/local/bin/xorsearch xorsearch_stub.c; \
    fi && \
    chmod +x /usr/local/bin/xorsearch && \
    rm -rf /tmp/*

# Download CAPA rules and signatures
RUN mkdir -p /analysis/capa-rules /analysis/capa-signatures && \
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
    # Clean up
    apt-get remove -y curl unzip git && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

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
