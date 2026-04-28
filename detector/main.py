import time
import threading
import yaml
import os
import sys

from monitor import LogMonitor
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from audit import AuditLogger
from dashboard import Dashboard


def load_config(path='config.yaml'):
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def baseline_recalc_loop(baseline, audit_logger):
    """Background thread: recalculate baseline every 60 seconds."""
    while True:
        try:
            recalced = baseline.recalculate()
            if recalced:
                mean, stddev = baseline.get_baseline()
                audit_logger.log(
                    action='BASELINE_RECALC',
                    ip=None,
                    condition='scheduled',
                    rate=mean,
                    baseline=stddev,
                    duration=None
                )
        except Exception as e:
            print(f"[baseline_loop] Error: {e}")
        time.sleep(10)


def main():
    print("[main] Starting HNG Anomaly Detection Engine...")

    # Load config
    config = load_config(
        os.path.join(os.path.dirname(__file__), 'config.yaml')
    )

    # Initialize components
    audit_logger = AuditLogger(config['audit_log'])
    baseline = BaselineTracker(
        window_minutes=config['baseline_window_minutes'],
        recalc_interval=config['baseline_recalc_interval'],
        floor_mean=config['baseline']['floor_mean'],
        floor_stddev=config['baseline']['floor_stddev'],
        min_samples=config['baseline']['min_samples']
    )
    notifier = Notifier(config['slack']['webhook_url'])
    blocker = Blocker(config['unban_schedule'])
    detector = AnomalyDetector(config, baseline)
    unbanner = Unbanner(blocker, notifier, audit_logger)
    monitor = LogMonitor(config['log_file'])
    dashboard = Dashboard(
        host=config['dashboard']['host'],
        port=config['dashboard']['port'],
        detector=detector,
        blocker=blocker,
        baseline=baseline
    )

    # Start background threads
    unbanner.start()
    dashboard.start()

    # Start baseline recalc thread
    t = threading.Thread(
        target=baseline_recalc_loop,
        args=(baseline, audit_logger),
        daemon=True
    )
    t.start()

    # Recently alerted IPs — prevent duplicate alerts within 60s
    recently_alerted = {}
    global_alerted_at = 0
    ALERT_COOLDOWN = 60

    print("[main] Monitoring traffic...")

    # Main loop: process log lines
    for entry in monitor.tail():
        ip = entry.get('source_ip', '')
        status = entry.get('status', 0)

        if not ip:
            continue

        is_error = status >= 400

        # Record in baseline and detector
        baseline.record_request(is_error=is_error)
        detector.record(ip, is_error=is_error)

        # Skip already banned IPs
        if blocker.is_banned(ip):
            continue

        # Check per-IP anomaly
        is_anomalous, reason, rate, mean, stddev = detector.check_ip(ip)
        now = time.time()

        if is_anomalous:
            last_alert = recently_alerted.get(ip, 0)
            if now - last_alert > ALERT_COOLDOWN:
                recently_alerted[ip] = now

                # Ban the IP
                duration = blocker.ban(ip)

                # Send Slack alert
                notifier.send_ban_alert(
                    ip=ip,
                    condition=reason,
                    rate=rate,
                    mean=mean,
                    stddev=stddev,
                    duration=duration
                )

                # Audit log
                audit_logger.log(
                    action='BAN',
                    ip=ip,
                    condition=reason,
                    rate=rate,
                    baseline=mean,
                    duration=duration
                )

                print(f"[main] BANNED {ip} | {reason} | rate={rate:.2f} | duration={duration}s")

        # Check global anomaly
        g_anomalous, g_reason, g_rate, g_mean, g_stddev = detector.check_global()
        if g_anomalous and (now - global_alerted_at > ALERT_COOLDOWN):
            global_alerted_at = now
            notifier.send_global_alert(
                condition=g_reason,
                rate=g_rate,
                mean=g_mean,
                stddev=g_stddev
            )
            audit_logger.log(
                action='GLOBAL_ANOMALY',
                ip=None,
                condition=g_reason,
                rate=g_rate,
                baseline=g_mean,
                duration=None
            )
            print(f"[main] GLOBAL ANOMALY | {g_reason} | rate={g_rate:.2f}")


if __name__ == '__main__':
    main()
