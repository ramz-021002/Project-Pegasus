#!/bin/bash
# Safe execution wrapper for malware samples
# Sets resource limits and executes sample with optional QEMU emulation

set -e

SAMPLE_PATH="$1"
TIMEOUT="${EXECUTION_TIMEOUT:-30}"

if [ -z "$SAMPLE_PATH" ]; then
    echo "Usage: $0 <sample_path>"
    exit 1
fi

# Set resource limits
ulimit -c 0          # No core dumps
ulimit -f 10240      # Max file size 10MB
ulimit -n 256        # Max open files
ulimit -u 50         # Max processes
ulimit -t $TIMEOUT   # CPU time limit

# Change to workspace
cd /analysis/workspace

# Detect if QEMU emulation is needed
HOST_ARCH=$(uname -m)
QEMU_CMD=""

if file -b "$SAMPLE_PATH" 2>/dev/null | grep -qi 'elf'; then
    SAMPLE_ARCH=$(file -b "$SAMPLE_PATH")
    case "$HOST_ARCH" in
        aarch64|arm64)
            if echo "$SAMPLE_ARCH" | grep -qi 'x86-64'; then
                [ -f /usr/bin/qemu-x86_64-static ] && QEMU_CMD="/usr/bin/qemu-x86_64-static"
            elif echo "$SAMPLE_ARCH" | grep -qi '80386\|Intel'; then
                [ -f /usr/bin/qemu-i386-static ] && QEMU_CMD="/usr/bin/qemu-i386-static"
            elif echo "$SAMPLE_ARCH" | grep -qi 'MIPS'; then
                [ -f /usr/bin/qemu-mips-static ] && QEMU_CMD="/usr/bin/qemu-mips-static"
            elif echo "$SAMPLE_ARCH" | grep -qi 'PowerPC'; then
                [ -f /usr/bin/qemu-ppc-static ] && QEMU_CMD="/usr/bin/qemu-ppc-static"
            fi
            ;;
        x86_64)
            if echo "$SAMPLE_ARCH" | grep -qi 'aarch64\|ARM aarch64'; then
                [ -f /usr/bin/qemu-aarch64-static ] && QEMU_CMD="/usr/bin/qemu-aarch64-static"
            elif echo "$SAMPLE_ARCH" | grep -qi 'ARM,'; then
                [ -f /usr/bin/qemu-arm-static ] && QEMU_CMD="/usr/bin/qemu-arm-static"
            elif echo "$SAMPLE_ARCH" | grep -qi 'MIPS'; then
                [ -f /usr/bin/qemu-mips-static ] && QEMU_CMD="/usr/bin/qemu-mips-static"
            elif echo "$SAMPLE_ARCH" | grep -qi 'PowerPC'; then
                [ -f /usr/bin/qemu-ppc-static ] && QEMU_CMD="/usr/bin/qemu-ppc-static"
            fi
            ;;
    esac
fi

# Execute sample (with QEMU if needed)
if [ -n "$QEMU_CMD" ]; then
    echo "[*] Using QEMU emulation: $QEMU_CMD"
    timeout $TIMEOUT $QEMU_CMD "$SAMPLE_PATH" || true
else
    timeout $TIMEOUT "$SAMPLE_PATH" || true
fi

# Kill any remaining child processes
pkill -P $$ || true

exit 0
