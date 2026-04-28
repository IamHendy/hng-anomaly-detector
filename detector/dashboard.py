import time
import psutil
import threading
from datetime import datetime
from flask import Flask, jsonify, render_template_string

START_TIME = time.time()

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>HNG Anomaly Detector</title>
    <meta http-equiv="refresh" content="3">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0e1a; color: #e0e6f0; font-family: 'Courier New', monospace; padding: 20px; }
        h1 { color: #00d4ff; text-align: center; padding: 20px 0; font-size: 1.8em; letter-spacing: 2px; }
        h1 span { color: #ff4444; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin: 20px 0; }
        .card { background: #111827; border: 1px solid #1e3a5f; border-radius: 8px; padding: 20px; }
        .card h3 { color: #00d4ff; margin-bottom: 15px; font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }
        .metric { font-size: 2em; color: #00ff88; font-weight: bold; }
        .metric.danger { color: #ff4444; }
        .metric.warn { color: #ffaa00; }
        .label { color: #8899aa; font-size: 0.8em; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
        th { color: #00d4ff; text-align: left; padding: 8px; border-bottom: 1px solid #1e3a5f; }
        td { padding: 8px; border-bottom: 1px solid #0d1f35; }
        tr:hover { background: #0d1f35; }
        .banned { color: #ff4444; }
        .status-bar { text-align: center; color: #8899aa; font-size: 0.8em; padding: 10px; }
        .uptime { color: #00ff88; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.75em; }
        .badge-red { background: #3d0000; color: #ff4444; border: 1px solid #ff4444; }
        .badge-green { background: #003d1a; color: #00ff88; border: 1px solid #00ff88; }
    </style>
</head>
<body>
    <h1>HNG <span>ANOMALY</span> DETECTOR</h1>
    <div class="status-bar">
        Last updated: {{ now }} &nbsp;|&nbsp;
        Uptime: <span class="uptime">{{ uptime }}</span> &nbsp;|&nbsp;
        Auto-refresh: 3s
    </div>

    <div class="grid">
        <div class="card">
            <h3>Global Request Rate</h3>
            <div class="metric {% if global_rate > mean * 3 %}danger{% elif global_rate > mean * 2 %}warn{% endif %}">
                {{ "%.2f"|format(global_rate) }} <small>req/s</small>
            </div>
            <div class="label">Baseline mean: {{ "%.2f"|format(mean) }} | stddev: {{ "%.2f"|format(stddev) }}</div>
        </div>

        <div class="card">
            <h3>Banned IPs</h3>
            <div class="metric {% if banned_count > 0 %}danger{% endif %}">{{ banned_count }}</div>
            <div class="label">Active blocks in iptables</div>
        </div>

        <div class="card">
            <h3>CPU Usage</h3>
            <div class="metric {% if cpu > 80 %}danger{% elif cpu > 60 %}warn{% endif %}">{{ cpu }}%</div>
            <div class="label">System CPU</div>
        </div>

        <div class="card">
            <h3>Memory Usage</h3>
            <div class="metric {% if mem > 80 %}danger{% elif mem > 60 %}warn{% endif %}">{{ mem }}%</div>
            <div class="label">{{ mem_used }} / {{ mem_total }} MB used</div>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Top 10 Source IPs</h3>
            <table>
                <tr><th>IP Address</th><th>Rate (req/s)</th><th>Status</th></tr>
                {% for ip, rate in top_ips %}
                <tr>
                    <td>{{ ip }}</td>
                    <td>{{ "%.3f"|format(rate) }}</td>
                    <td>
                        {% if ip in banned_ips %}
                        <span class="badge badge-red">BANNED</span>
                        {% else %}
                        <span class="badge badge-green">OK</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <div class="card">
            <h3>Banned IPs Detail</h3>
            <table>
                <tr><th>IP Address</th><th>Duration</th><th>Bans</th></tr>
                {% for ip, info in banned_ips.items() %}
                <tr class="banned">
                    <td>{{ ip }}</td>
                    <td>{% if info.duration == -1 %}permanent{% else %}{{ info.duration }}s{% endif %}</td>
                    <td>{{ info.ban_count }}</td>
                </tr>
                {% else %}
                <tr><td colspan="3" style="color:#8899aa">No banned IPs</td></tr>
                {% endfor %}
            </table>
        </div>
    </div>
</body>
</html>
"""

class Dashboard:
    """Live metrics web dashboard served via Flask."""

    def __init__(self, host, port, detector, blocker, baseline):
        self.host = host
        self.port = port
        self.detector = detector
        self.blocker = blocker
        self.baseline = baseline
        self.app = Flask(__name__)
        self._setup_routes()

    def _setup_routes(self):
        @self.app.route('/')
        def index():
            now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
            uptime_s = int(time.time() - START_TIME)
            h, m, s = uptime_s // 3600, (uptime_s % 3600) // 60, uptime_s % 60
            uptime = f"{h}h {m}m {s}s"

            mean, stddev = self.baseline.get_baseline()
            global_rate = self.detector.get_global_rate()
            top_ips = self.detector.get_top_ips(10)
            banned_ips = self.blocker.get_banned()
            banned_count = len(banned_ips)

            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            mem_pct = mem.percent
            mem_used = mem.used // (1024 * 1024)
            mem_total = mem.total // (1024 * 1024)

            return render_template_string(
                HTML,
                now=now,
                uptime=uptime,
                global_rate=global_rate,
                mean=mean,
                stddev=stddev,
                top_ips=top_ips,
                banned_ips=banned_ips,
                banned_count=banned_count,
                cpu=cpu,
                mem=mem_pct,
                mem_used=mem_used,
                mem_total=mem_total
            )

        @self.app.route('/api/metrics')
        def metrics():
            mean, stddev = self.baseline.get_baseline()
            return jsonify({
                'global_rate': self.detector.get_global_rate(),
                'mean': mean,
                'stddev': stddev,
                'banned_ips': list(self.blocker.get_banned().keys()),
                'top_ips': self.detector.get_top_ips(10),
                'cpu': psutil.cpu_percent(interval=None),
                'memory': psutil.virtual_memory().percent,
                'uptime': int(time.time() - START_TIME)
            })

    def start(self):
        """Start Flask dashboard in background thread."""
        t = threading.Thread(
            target=lambda: self.app.run(
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False
            ),
            daemon=True
        )
        t.start()
        print(f"[dashboard] Running at http://{self.host}:{self.port}")
