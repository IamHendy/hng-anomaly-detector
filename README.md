# HNG Anomaly Detection Engine

A real-time HTTP traffic anomaly detection and DDoS mitigation daemon built for HNG's cloud.ng Nextcloud platform.

## Live URLs
- **Metrics Dashboard:** http://hendyogema.mooo.com
- **Server IP:** 167.71.29.236 (Nextcloud accessible via IP only)
- **GitHub:** https://github.com/IamHendy/hng-anomaly-detector

## Language Choice
**Python** — chosen for its rich standard library, readable syntax, and excellent threading support. The `collections.deque` data structure is perfect for implementing sliding windows efficiently, and Flask makes serving the live dashboard simple without heavyweight frameworks.

## How the Sliding Window Works
The sliding window uses Python's `collections.deque` — a double-ended queue that allows fast appends and removals from both ends.

Two deque-based windows are maintained:
- **Per-IP window:** one deque per IP address storing timestamps of each request
- **Global window:** one deque storing timestamps of all requests

On every incoming request, the current timestamp is appended to the right of the deque. A cutoff time is calculated as `now - 60 seconds`. All entries older than the cutoff are evicted from the left of the deque using `popleft()`. The current rate is then `len(deque) / 60`.

This gives an accurate rolling count of requests in the last 60 seconds without ever needing a database or external storage.

## How the Baseline Works
- **Window size:** 30 minutes of per-second request counts
- **Recalculation interval:** every 60 seconds
- **Per-hour slots:** the baseline maintains separate mean/stddev values per hour slot
- **Floor values:** minimum mean of 0.1 req/s and stddev of 0.1 to avoid division by zero on idle servers
- **Preference:** the current hour's baseline is used if it has at least 30 samples; otherwise falls back to the previous hour

The rolling mean and standard deviation are computed from scratch each recalculation using pure Python math — no external libraries.

## Anomaly Detection Logic
An IP or global traffic rate is flagged as anomalous if either condition fires first:
1. **Z-score > 3.0:** `(current_rate - mean) / stddev > 3.0`
2. **Rate multiplier > 5x:** `current_rate > 5 * mean`

If an IP's 4xx/5xx error rate exceeds 3x the baseline error rate, thresholds are automatically tightened by 30% (zscore threshold × 0.7, rate multiplier × 0.7).

## How iptables Blocks an IP
When an IP is flagged as anomalous, the blocker runs:
iptables -I INPUT -s <IP> -j DROP

This inserts a rule at the top of the INPUT chain that drops all packets from that IP at the kernel level — before they even reach Nginx or Nextcloud.

Auto-unban follows a backoff schedule: 10 minutes → 30 minutes → 2 hours → permanent.

## Setup Instructions

### Prerequisites
- Ubuntu 22.04/24.04 VPS (minimum 2 vCPU, 2GB RAM)
- Docker and Docker Compose installed
- Python 3.10+

### Step 1 — Clone the repo
```bash
git clone https://github.com/IamHendy/hng-anomaly-detector.git
cd hng-anomaly-detector
```

### Step 2 — Configure
```bash
nano detector/config.yaml
```
Add your Slack webhook URL.

### Step 3 — Start the Docker stack
```bash
docker compose up -d
```

### Step 4 — Install Python dependencies
```bash
cd detector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 5 — Update log path
```bash
docker volume inspect HNG-nginx-logs | grep Mountpoint
```
Update `log_file` and `audit_log` in `config.yaml` with the mountpoint path.

### Step 6 — Run as a system service
```bash
cp ../hng-detector.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable hng-detector
systemctl start hng-detector
```

### Step 7 — Verify
```bash
systemctl status hng-detector
curl http://localhost:8080
```

## Architecture
See `docs/architecture.png`

## Blog Post
https://dev.to/iamhendy/how-i-built-a-real-time-ddos-detection-engine-for-nextcloud

## Screenshots
- `screenshots/Tool-running.png` — Daemon running
- `screenshots/Ban-slack.png` — Slack ban notification
- `screenshots/Unban-slack.png` — Slack unban notification
- `screenshots/Global-alert-slack.png` — Global anomaly notification
- `screenshots/Iptables-banned.png` — iptables showing blocked IP
- `screenshots/Audit-log.png` — Structured audit log
- `screenshots/Baseline-graph.png` — Baseline over time
