import time
import threading
from datetime import datetime


class AuditLogger:
    """
    Writes structured log entries for every ban, unban,
    and baseline recalculation event.
    Format: [timestamp] ACTION ip | condition | rate | baseline | duration
    """

    def __init__(self, log_path):
        self.log_path = log_path
        self.lock = threading.Lock()

    def log(self, action, ip=None, condition=None,
            rate=None, baseline=None, duration=None):
        """Write a structured audit log entry."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        ip_str = ip or 'global'
        condition_str = condition or '-'
        rate_str = f"{rate:.4f}" if rate is not None else '-'
        baseline_str = f"{baseline:.4f}" if baseline is not None else '-'
        duration_str = str(duration) if duration is not None else '-'

        line = (
            f"[{timestamp}] {action} {ip_str} | "
            f"{condition_str} | "
            f"rate={rate_str} | "
            f"baseline={baseline_str} | "
            f"duration={duration_str}\n"
        )

        with self.lock:
            try:
                with open(self.log_path, 'a') as f:
                    f.write(line)
            except Exception as e:
                print(f"[audit] Failed to write log: {e}")

        print(f"[audit] {line.strip()}")
