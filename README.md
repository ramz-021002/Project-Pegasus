# Project Pegasus

**Secure Malware Analysis Platform**

Project Pegasus is a comprehensive malware analysis platform that performs automated static and dynamic analysis in isolated Docker environments. It provides a secure, web-based interface for analysts to examine suspicious files, extract indicators of compromise (IOCs), and observe malicious behavior while ensuring complete host isolation.

## Features

- **Secure Isolation**: All analysis runs in unprivileged, network-isolated Docker containers with resource limits and capability dropping.
- **Intelligent Threat Classification**: Automatically classifies samples as **Malicious**, **Suspicious**, or **Clean** based on comprehensive analysis indicators including ATT&CK techniques, behavioral patterns, and IOCs.
- **Robust Static Analysis**:
    - PE Header & Import parsing with suspicious API detection
    - **Intelligent String Ranking**: Prioritizes interesting APIs, paths, IPs, and URLs
    - **CAPA Integration**: ATT&CK technique mapping and malware behavior catalog (MBC) detection
    - **XOR Analysis**: XORSearch/XORStrings integration for encoded payload detection
    - YARA scanning and Entropy calculation for packer detection
- **Advanced Dynamic Analysis**:
    - **Unified Execution Monitoring**: Combines `strace` syscall logging with `psutil` process tracking
    - Wine & QEMU support for cross-architecture PE analysis
    - Behavioral analysis with process injection and command execution detection
- **Network Traffic Capture**:
    - **INetSim Integration**: Provides a simulated internet environment (DNS, HTTP, etc.)
    - **IPv6 Support**: Full capture and parsing of IPv6 traffic and DNS (AAAA)
- **Report Management**:
    - **Smart Classification**: Real-time threat level assessment with color-coded results
    - **Hash Search**: Look up existing reports by SHA256
    - **One-Click Re-analysis**: Instantly trigger fresh analysis runs for any sample
- **Unified Reporting**: Clean, real-time Web UI for monitoring progress and viewing comprehensive results

## Demo
https://github.com/user-attachments/assets/b9e3c0b8-5239-4241-93b2-3172e2b81c85



## Architecture

```mermaid
graph TD
    User([User Browser]) --> UI[Web Frontend]
    UI --> API[FastAPI Backend]
    API --> DB[(PostgreSQL)]
    API --> Queue[Redis / Celery]
    Queue --> Worker[Celery Worker]
    Worker --> Docker[Docker Manager]
    Docker --> Static[Static Analysis Container]
    Docker --> Dynamic[Dynamic Analysis Container]
    Docker --> Gateway[Network Gateway Container]
    Gateway <--> Dynamic
```

## Prerequisites

- **Docker** (20.10+) & **Docker Compose** (V2)
- **Python 3.11+** (for test scripts and local development)
- **Make** (optional, for automation)

## Quick Start

### 1. Initial Setup
```bash
./setup.sh
```
This script will verify dependencies, generate secure `.env` keys, and build the required Docker images.

### 2. Start the Platform
```bash
docker compose up -d
```
Access the Web UI at: `http://localhost:3000` (or open the local file directly).

### 3. Verify System
```bash
python3 test_system.py
```
### 4. Delete all the containers and volumes
This would stop and remove ALL services and data
```bash
sudo docker system prune -a --volumes --force
sudo docker-compose down -v --rmi all
```

## API usage

- **Docs**: `http://localhost:8000/api/docs`
- **Upload**: `POST /api/upload/`
- **Results**: `GET /api/analysis/{sample_id}`
- **Search**: `GET /api/analysis/?sha256={hash}`

## Development Roadmap

### Phase 1: Core Infrastructure
- [x] Project structure & Database models
- [x] Celery & Redis orchestration
- [x] Secure file quarantine (AES-128 encryption)

### Phase 2: Static Analysis
- [x] Ubuntu-based analyzer with comprehensive toolset
- [x] Intelligent String Ranking
- [x] Robust CAPA integration with ATT&CK mapping
- [x] XORSearch/XORStrings for encoded payload detection
- [x] Suspicious API import detection

### Phase 3: Dynamic Analysis
- [x] Unified behavior monitoring (strace + psutil)
- [x] Wine/QEMU binary emulation
- [x] Process & File tracking
- [x] Command execution and process injection detection

### Phase 4: Network Analysis
- [x] INetSim Gateway integration
- [x] IPv6 & AAAA DNS support
- [x] PCAP capture and automated parsing

### Phase 5: UI & Classification
- [x] Real-time analysis polling
- [x] Hash Search & Re-analysis
- [x] **Intelligent Threat Classification**: Automated threat level assessment
- [x] Color-coded results (Malicious/Suspicious/Clean)
- [x] Prioritized multi-tab results view

### Phase 6: Hardening & Advanced Features (Current)
- [ ] User Authentication & Multi-Tenancy
- [ ] Advanced Memory Forensics integration
- [ ] Automated Report Export (PDF/JSON)
- [ ] Machine Learning-based classification enhancement
- [ ] Custom YARA rule management interface

## Security Warning

- **This system analyzes LIVE MALWARE**.
- Always run on dedicated hardware or within a detached VM.
- Verify network isolation (`test_system.py`) before analyzing unknown samples.
- Never expose the API to the public internet without proper authentication.

## License
Educational and authorized security research purposes only.

## Acknowledgments
- **Didier Stevens** for XORSearch/XORStrings and analysis tools
- **Mandiant** for CAPA capability analysis framework
- **INetSim** for the simulated network services
- **FastAPI** & **Celery** for the backend orchestration
- **MITRE ATT&CK** framework for threat intelligence mapping
