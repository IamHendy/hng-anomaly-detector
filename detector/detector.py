import time
import math
from collections import deque
from threading import Lock


class AnomalyDetector:
    """
    Detects anomalies using two deque-based sliding windows:
    - Per-IP window: tracks requests per IP in last 60 seconds
    - Global window: tracks all requests in last 60 seconds

    Flags anomaly if:
    - Z-score > 3.0, OR
    - Rate > 5x baseline mean
    Also tightens thresholds if error rate is 3x baseline error rate.
    """

    def __init__(self, config, baseline_tracker):
        self.config = config
        self.baseline = baseline_tracker
        self.window_seconds = config['sliding_window_seconds']
        self.zscore_threshold = config['thresholds']['zscore']
        self.rate_multiplier = config['thresholds']['rate_multiplier']
        self.error_multiplier = config['thresholds']['error_rate_multiplier']

        # Global sliding window: deque of timestamps
        self.global_window = deque()

        # Per-IP sliding windows: {ip: deque of timestamps}
        self.ip_windows = {}

        # Per-IP error tracking: {ip: deque of (timestamp, is_error)}
        self.ip_error_windows = {}

        self.lock = Lock()

    def record(self, ip, is_error=False):
        """Record a request from an IP."""
        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds

            # Update global window
            self.global_window.append(now)
            while self.global_window and self.global_window[0] < cutoff:
                self.global_window.popleft()

            # Update per-IP window
            if ip not in self.ip_windows:
                self.ip_windows[ip] = deque()
            self.ip_windows[ip].append(now)
            while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
                self.ip_windows[ip].popleft()

            # Update per-IP error window
            if ip not in self.ip_error_windows:
                self.ip_error_windows[ip] = deque()
            self.ip_error_windows[ip].append((now, is_error))
            while (self.ip_error_windows[ip] and
                   self.ip_error_windows[ip][0][0] < cutoff):
                self.ip_error_windows[ip].popleft()

    def get_ip_rate(self, ip):
        """Get current request rate for an IP (reqs/sec)."""
        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds
            if ip not in self.ip_windows:
                return 0.0
            # Evict old entries
            while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
                self.ip_windows[ip].popleft()
            return len(self.ip_windows[ip]) / self.window_seconds

    def get_global_rate(self):
        """Get current global request rate (reqs/sec)."""
        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds
            while self.global_window and self.global_window[0] < cutoff:
                self.global_window.popleft()
            return len(self.global_window) / self.window_seconds

    def get_ip_error_rate(self, ip):
        """Get error rate for an IP."""
        with self.lock:
            if ip not in self.ip_error_windows:
                return 0.0
            errors = sum(1 for _, e in self.ip_error_windows[ip] if e)
            total = len(self.ip_error_windows[ip])
            return errors / total if total > 0 else 0.0

    def _is_tightened(self, ip):
        """Check if thresholds should be tightened due to error surge."""
        ip_error_rate = self.get_ip_error_rate(ip)
        baseline_error_rate = self.baseline.get_error_rate()
        if baseline_error_rate > 0:
            return ip_error_rate > (self.error_multiplier * baseline_error_rate)
        return ip_error_rate > 0.5

    def check_ip(self, ip):
        """
        Check if an IP is anomalous.
        Returns (is_anomalous, reason, rate, mean, stddev)
        """
        mean, stddev = self.baseline.get_baseline()
        rate = self.get_ip_rate(ip)

        # Tighten thresholds if error surge
        zscore_thresh = self.zscore_threshold
        rate_mult = self.rate_multiplier
        if self._is_tightened(ip):
            zscore_thresh *= 0.7
            rate_mult *= 0.7

        # Z-score check
        if stddev > 0:
            zscore = (rate - mean) / stddev
        else:
            zscore = 0

        if zscore > zscore_thresh:
            return True, f"zscore={zscore:.2f}", rate, mean, stddev

        # Rate multiplier check
        if mean > 0 and rate > rate_mult * mean:
            return True, f"rate={rate:.2f} > {rate_mult}x mean={mean:.2f}", rate, mean, stddev

        return False, None, rate, mean, stddev

    def check_global(self):
        """
        Check if global traffic is anomalous.
        Returns (is_anomalous, reason, rate, mean, stddev)
        """
        mean, stddev = self.baseline.get_baseline()
        rate = self.get_global_rate()

        if stddev > 0:
            zscore = (rate - mean) / stddev
        else:
            zscore = 0

        if zscore > self.zscore_threshold:
            return True, f"global_zscore={zscore:.2f}", rate, mean, stddev

        if mean > 0 and rate > self.rate_multiplier * mean:
            return True, f"global_rate={rate:.2f} > {self.rate_multiplier}x mean={mean:.2f}", rate, mean, stddev

        return False, None, rate, mean, stddev

    def get_top_ips(self, n=10):
        """Return top N IPs by current request rate."""
        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds
            rates = {}
            for ip, window in self.ip_windows.items():
                while window and window[0] < cutoff:
                    window.popleft()
                rates[ip] = len(window) / self.window_seconds
            return sorted(rates.items(), key=lambda x: x[1], reverse=True)[:n]
