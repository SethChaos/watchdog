Nmap Scanner for Xseth Project

A unified security scanning service that provides two levels of nmap scanning intensity through a Redis-based job queue system.
🎯 Scan Types
1. Basic Scan

Quick reconnaissance - 1-2 minutes
bash

nmap -sS -sV --top-ports 1000 -T4 --open target.com

    SYN scan + Service detection

    Top 1000 ports (most common services)

    Aggressive timing (T4)

    Only open ports (clean output)

2. Deep Scan

Comprehensive audit - 5-10+ minutes
bash

nmap -sS -sV -sC -O -p- -T3 --min-rate 500 target.com

    SYN scan + Service detection + Script scan

    All ports (1-65535)

    OS detection

    Normal timing (T3) + Minimum rate (500 pkt/sec)

🚀 Quick Start
Prerequisites

    Go 1.21+

    Redis server

    Nmap installed

    Root privileges

Installation
bash

# Install dependencies
go mod init nmap-scanner
go get github.com/redis/go-redis/v9

# Start scanner
sudo go run unified_scanner_hybrid.go

Submit Scans
bash

# Basic scan
redis-cli LPUSH nmap_scans_queue '{"scan_id":"scan1","target":"example.com","scan_type":"basic","timeout":120}'

# Deep scan
redis-cli LPUSH nmap_scans_queue '{"scan_id":"scan2","target":"example.com","scan_type":"deep","timeout":600}'

📋 Job Format
json

{
  "scan_id": "unique_job_id",
  "target": "domain.com or IP",
  "scan_type": "basic|deep",
  "callback_url": "optional",
  "timeout": 300
}

📊 Results

Check scan results in Redis:
bash

redis-cli LRANGE scan_results 0 -1

🛠️ Configuration
Timeout Guidelines

    Basic scans: 120-180 seconds

    Deep scans: 300-600 seconds

Redis Configuration

    Queue: nmap_scans_queue

    Results: scan_results

⚠️ Requirements

    Root privileges for SYN scans and OS detection

    Nmap installed on system

    Redis server running on localhost:6379

Two scan intensities, one unified service 🔍