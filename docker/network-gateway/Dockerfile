# Network Gateway Container with INetSim
# Provides fake internet services for malware analysis

FROM ubuntu:22.04

# Install INetSim and network tools
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    inetsim \
    tcpdump \
    dnsmasq \
    iptables \
    iproute2 \
    net-tools \
    iputils-ping \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy configuration files
COPY inetsim.conf /etc/inetsim/inetsim.conf
COPY start_gateway.sh /start_gateway.sh

# Make script executable
RUN chmod +x /start_gateway.sh

# Create log directory (world-writable so inetsim can write regardless of user)
RUN mkdir -p /var/log/inetsim && chmod 777 /var/log/inetsim

# Fix permissions for INetSim data directories
RUN chown -R inetsim:inetsim /usr/share/inetsim/data \
    && chmod -R 775 /usr/share/inetsim/data

# Expose common ports
EXPOSE 53/udp 53/tcp 80/tcp 443/tcp 21/tcp 25/tcp

# Start gateway
CMD ["/start_gateway.sh"]
