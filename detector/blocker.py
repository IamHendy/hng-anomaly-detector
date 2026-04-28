import subprocess
import time
from threading import Lock


class Blocker:
    """
    Manages iptables DROP rules for banned IPs.
    Tracks ban count per IP for backoff schedule.
    """

    def __init__(self, unban_schedule):
        # unban_schedule: list of seconds [600, 1800, 7200, -1]
        self.unban_schedule = unban_schedule
        self.lock = Lock()

        # {ip: {'banned_at': time, 'ban_count': n, 'duration': seconds}}
        self.banned_ips = {}

    def ban(self, ip):
        """
        Add iptables DROP rule for IP.
        Returns ban duration in seconds (-1 = permanent).
        """
        with self.lock:
            ban_count = 0
            if ip in self.banned_ips:
                ban_count = self.banned_ips[ip].get('ban_count', 0)

            # Get duration from backoff schedule
            idx = min(ban_count, len(self.unban_schedule) - 1)
            duration = self.unban_schedule[idx]

            # Add iptables rule
            self._add_rule(ip)

            self.banned_ips[ip] = {
                'banned_at': time.time(),
                'ban_count': ban_count + 1,
                'duration': duration
            }

            return duration

    def unban(self, ip):
        """Remove iptables DROP rule for IP."""
        with self.lock:
            self._remove_rule(ip)
            if ip in self.banned_ips:
                del self.banned_ips[ip]

    def _add_rule(self, ip):
        """Insert iptables DROP rule."""
        try:
            # Check if rule already exists
            check = subprocess.run(
                ['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True
            )
            if check.returncode != 0:
                subprocess.run(
                    ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                    check=True, capture_output=True
                )
                print(f"[blocker] Banned IP: {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[blocker] Error banning {ip}: {e}")

    def _remove_rule(self, ip):
        """Remove iptables DROP rule."""
        try:
            # Remove all matching rules
            while True:
                result = subprocess.run(
                    ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                    capture_output=True
                )
                if result.returncode != 0:
                    break
            print(f"[blocker] Unbanned IP: {ip}")
        except Exception as e:
            print(f"[blocker] Error unbanning {ip}: {e}")

    def get_banned(self):
        """Return dict of currently banned IPs."""
        with self.lock:
            return dict(self.banned_ips)

    def is_banned(self, ip):
        """Check if IP is currently banned."""
        with self.lock:
            return ip in self.banned_ips
