import time
import math
from collections import deque
from threading import Lock

class BaselineTracker:
    """
    Tracks per-second request counts over a 30-minute rolling window.
    Recalculates mean and stddev every 60 seconds.
    Maintains per-hour slots and prefers current hour's baseline.
    """

    def __init__(self, window_minutes=30, recalc_interval=60,
                 floor_mean=0.1, floor_stddev=0.1, min_samples=30):
        self.window_minutes = window_minutes
        self.recalc_interval = recalc_interval
        self.floor_mean = floor_mean
        self.floor_stddev = floor_stddev
        self.min_samples = min_samples

        # Rolling window: stores (timestamp, count) per second
        self.window = deque()
        self.lock = Lock()

        # Per-hour slots: {hour: {'mean': x, 'stddev': y, 'samples': n}}
        self.hourly_slots = {}

        # Current effective baseline
        self.effective_mean = floor_mean
        self.effective_stddev = floor_stddev

        # Per-second counter
        self.current_second = int(time.time())
        self.current_count = 0

        # Error rate tracking
        self.error_window = deque()  # (timestamp, is_error)
        self.baseline_error_rate = 0.0

        self.last_recalc = time.time()

    def record_request(self, is_error=False):
        """Record a single incoming request."""
        with self.lock:
            now = int(time.time())
            if now != self.current_second:
                # Save completed second to window
                self.window.append((self.current_second, self.current_count))
                self.current_second = now
                self.current_count = 0
                # Evict entries older than window
                cutoff = now - (self.window_minutes * 60)
                while self.window and self.window[0][0] < cutoff:
                    self.window.popleft()

            self.current_count += 1

            # Track errors
            now_f = time.time()
            self.error_window.append((now_f, is_error))
            cutoff_f = now_f - (self.window_minutes * 60)
            while self.error_window and self.error_window[0][0] < cutoff_f:
                self.error_window.popleft()

    def recalculate(self):
        """Recalculate mean and stddev from the rolling window."""
        with self.lock:
            now = time.time()
            if now - self.last_recalc < self.recalc_interval:
                return False

            counts = [c for _, c in self.window]
            if len(counts) < self.min_samples:
                self.effective_mean = self.floor_mean
                self.effective_stddev = self.floor_stddev
                self.last_recalc = now
                return True

            mean = sum(counts) / len(counts)
            variance = sum((c - mean) ** 2 for c in counts) / len(counts)
            stddev = math.sqrt(variance)

            # Store in hourly slot
            hour = int(now // 3600)
            self.hourly_slots[hour] = {
                'mean': mean,
                'stddev': stddev,
                'samples': len(counts)
            }

            # Prefer current hour if enough data
            if self.hourly_slots[hour]['samples'] >= self.min_samples:
                self.effective_mean = max(mean, self.floor_mean)
                self.effective_stddev = max(stddev, self.floor_stddev)
            else:
                # Fall back to previous hour
                prev_hour = hour - 1
                if prev_hour in self.hourly_slots:
                    self.effective_mean = max(
                        self.hourly_slots[prev_hour]['mean'], self.floor_mean)
                    self.effective_stddev = max(
                        self.hourly_slots[prev_hour]['stddev'], self.floor_stddev)

            # Recalculate error rate
            errors = sum(1 for _, e in self.error_window if e)
            total = len(self.error_window)
            self.baseline_error_rate = errors / total if total > 0 else 0.0

            self.last_recalc = now
            return True

    def get_baseline(self):
        """Return current effective mean and stddev."""
        return self.effective_mean, self.effective_stddev

    def get_error_rate(self):
        return self.baseline_error_rate
