import time
import threading
from threading import Lock


class Unbanner:
    """
    Monitors banned IPs and releases them on backoff schedule.
    Runs in its own background thread.
    Schedule: 10 min, 30 min, 2 hours, then permanent.
    """

    def __init__(self, blocker, notifier, audit_logger):
        self.blocker = blocker
        self.notifier = notifier
        self.audit_logger = audit_logger
        self.lock = Lock()
        self._stop = False

    def start(self):
        """Start the unbanner thread."""
        t = threading.Thread(target=self._run, daemon=True)
        t.start()
        print("[unbanner] Started")

    def stop(self):
        self._stop = True

    def _run(self):
        """Check every 30 seconds for IPs ready to be unbanned."""
        while not self._stop:
            try:
                self._check_unbans()
            except Exception as e:
                print(f"[unbanner] Error: {e}")
            time.sleep(30)

    def _check_unbans(self):
        """Unban IPs whose ban duration has expired."""
        now = time.time()
        banned = self.blocker.get_banned()

        for ip, info in banned.items():
            duration = info.get('duration', 600)

            # -1 means permanent ban
            if duration == -1:
                continue

            banned_at = info.get('banned_at', now)
            elapsed = now - banned_at

            if elapsed >= duration:
                self.blocker.unban(ip)

                # Notify Slack
                self.notifier.send_unban_alert(
                    ip=ip,
                    duration=duration,
                    ban_count=info.get('ban_count', 1)
                )

                # Audit log
                self.audit_logger.log(
                    action='UNBAN',
                    ip=ip,
                    condition='ban_expired',
                    rate=0,
                    baseline=0,
                    duration=duration
                )

                print(f"[unbanner] Unbanned {ip} after {duration}s")
