# eBPF Network Flow Collector

This project captures network flows using an eBPF XDP program and saves them to a local file with log rotation. It can also export flows as NetFlow v5 to a remote collector.

## Requirements
- Ubuntu (with kernel >= 4.8)
- Python 3
- bcc (`python3-bcc`)
- Linux kernel headers (`linux-headers-$(uname -r)`)

## Setup

1. **Install dependencies:**
   ```sh
   sudo apt update
   sudo apt install -y python3-bcc linux-headers-$(uname -r)
   ```

2. **Clone or copy this repository.**

3. **Run the collector (as root):**
   ```sh
   sudo INTERFACE=wlo1 OUTPUT_FILE=/var/log/flows.txt LOG_MAX_BYTES=1048576 LOG_BACKUP_COUNT=10 NETFLOW_COLLECTOR=192.168.1.100 NETFLOW_PORT=2056 python3 flow_collector.py
   ```
   - `LOG_MAX_BYTES`: Maximum size in bytes before rotating the log (default: 5MB)
   - `LOG_BACKUP_COUNT`: Number of rotated log files to keep (default: 5)
   - `NETFLOW_COLLECTOR`: IP address of NetFlow collector (optional)
   - `NETFLOW_PORT`: UDP port of NetFlow collector (default: 2055)

4. **Check the output:**
   ```sh
   cat /tmp/flows.txt
   ls /tmp/flows.txt*
   ```
   Rotated logs will be named `/tmp/flows.txt.1`, `/tmp/flows.txt.2`, etc.

   If NetFlow export is enabled, flows will be sent to the specified collector in NetFlow v5 format.

## Files
- `flow_collector.c`: eBPF program for flow capture
- `flow_collector.py`: User-space loader and collector
- `requirements.txt`: Python dependencies

## Notes
- You must run as root to load eBPF programs.
- The script writes each flow as a log line every 10 seconds, appending to the log file with rotation.
- For production, consider more advanced flow export formats or integration with flow collectors. 