#!/bin/bash
# Start network gateway with INetSim and traffic capture

set -e

echo "🛡️ Project Pegasus Network Gateway starting..."

# Get container IP (more robustly)
CONTAINER_IP=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')

if [ -z "$CONTAINER_IP" ]; then
    echo "❌ ERROR: Could not determine container IP!"
    exit 1
fi

echo "📍 Container IP: $CONTAINER_IP"

# Update inetsim.conf with container IP for all services
echo "⚙️ Configuring INetSim..."
sed -i "s/172.20.0.10/$CONTAINER_IP/g" /etc/inetsim/inetsim.conf
echo "Updated inetsim.conf with IP: $CONTAINER_IP"

# Ensure capture directory exists and is writable
mkdir -p /tmp/captures
chmod 0777 /tmp/captures || true

# Prepare pcap filename
SAFE_IP=$(echo "$CONTAINER_IP" | tr '.' '_')
PCAP_FILE=/tmp/captures/gateway_$(date +%Y%m%d_%H%M%S).pcap

# Start tcpdump in background
echo "📡 Starting packet capture -> $PCAP_FILE"
tcpdump -i any -w "$PCAP_FILE" -s 65535 -n &
TCPDUMP_PID=$!

# Give tcpdump a moment to start
sleep 1
if ! kill -0 $TCPDUMP_PID 2>/dev/null; then
    echo "⚠️ WARNING: tcpdump failed to start or exited early"
else
    chmod 0666 "$PCAP_FILE" || true
    echo "✅ Packet capture active (PID: $TCPDUMP_PID)"
fi

# Check for port conflicts before starting inetsim
echo "🔍 Checking for port conflicts..."
for port in 53 80 443 21 25; do
    if netstat -tuln | grep -q ":$port "; then
        echo "⚠️ WARNING: Port $port is already in use!"
    fi
done

# Start INetSim
echo "🚀 Starting INetSim..."
# Run inetsim and pipe output to a log file we can tail
inetsim --log-dir=/var/log/inetsim --data-dir=/usr/share/inetsim/data > /var/log/inetsim/stdout.log 2>&1 &
INETSIM_PID=$!

# Wait a few seconds to see if it stays up
sleep 3
if ! kill -0 $INETSIM_PID 2>/dev/null; then
    echo "❌ ERROR: INetSim failed to start!"
    echo "=== Last 20 lines of inetsim stdout/stderr ==="
    tail -n 20 /var/log/inetsim/stdout.log
    if [ -f /var/log/inetsim/main.log ]; then
        echo "=== Last 20 lines of inetsim main.log ==="
        tail -n 20 /var/log/inetsim/main.log
    fi
    exit 1
fi

echo "✅ Gateway Ready (INetSim PID: $INETSIM_PID)"

# Function to handle shutdown
shutdown() {
    echo "🛑 Shutting down gateway..."
    kill $TCPDUMP_PID 2>/dev/null || true
    kill $INETSIM_PID 2>/dev/null || true
    
    echo "📊 Gateway stopped."
    exit 0
}

# Trap signals
trap shutdown SIGTERM SIGINT

# Keep script running and monitor INetSim
while kill -0 $INETSIM_PID 2>/dev/null; do
    sleep 5
done

echo "❌ ERROR: INetSim process died unexpectedly!"
shutdown
