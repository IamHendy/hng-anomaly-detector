import requests
import json
import time
from datetime import datetime


class Notifier:
    """
    Sends Slack alerts for ban, unban, and global anomaly events.
    Webhook URL loaded from config.
    """

    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    def _send(self, message):
        """Send a message to Slack webhook."""
        try:
            payload = {"text": message}
            response = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            if response.status_code != 200:
                print(f"[notifier] Slack error: {response.status_code} {response.text}")
        except Exception as e:
            print(f"[notifier] Failed to send Slack alert: {e}")

    def send_ban_alert(self, ip, condition, rate, mean, stddev, duration):
        """Send a ban notification to Slack."""
        duration_str = "permanent" if duration == -1 else f"{duration}s"
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        message = (
            f":rotating_light: *IP BANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Condition:* {condition}\n"
            f"*Current Rate:* {rate:.2f} req/s\n"
            f"*Baseline Mean:* {mean:.2f} req/s\n"
            f"*Baseline Stddev:* {stddev:.2f}\n"
            f"*Ban Duration:* {duration_str}\n"
            f"*Timestamp:* {timestamp}"
        )
        self._send(message)
        print(f"[notifier] Ban alert sent for {ip}")

    def send_unban_alert(self, ip, duration, ban_count):
        """Send an unban notification to Slack."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        message = (
            f":white_check_mark: *IP UNBANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Ban Duration Served:* {duration}s\n"
            f"*Total Bans:* {ban_count}\n"
            f"*Timestamp:* {timestamp}"
        )
        self._send(message)
        print(f"[notifier] Unban alert sent for {ip}")

    def send_global_alert(self, condition, rate, mean, stddev):
        """Send a global anomaly notification to Slack."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        message = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"*Condition:* {condition}\n"
            f"*Global Rate:* {rate:.2f} req/s\n"
            f"*Baseline Mean:* {mean:.2f} req/s\n"
            f"*Baseline Stddev:* {stddev:.2f}\n"
            f"*Timestamp:* {timestamp}"
        )
        self._send(message)
        print(f"[notifier] Global alert sent")
