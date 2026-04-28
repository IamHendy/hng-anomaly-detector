import time
import os
import json

class LogMonitor:
    """Continuously tails the Nginx JSON access log and yields parsed entries."""

    def __init__(self, log_path):
        self.log_path = log_path

    def tail(self):
        """Open log file and yield new lines as they appear."""
        # Wait for log file to exist
        while not os.path.exists(self.log_path):
            print(f"[monitor] Waiting for log file: {self.log_path}")
            time.sleep(2)

        with open(self.log_path, 'r') as f:
            # Seek to end of file on startup
            f.seek(0, 2)
            print(f"[monitor] Tailing {self.log_path}")
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                line = line.strip()
                if not line:
                    continue
                entry = self.parse_line(line)
                if entry:
                    yield entry

    def parse_line(self, line):
        """Parse a JSON log line into a dict."""
        try:
            data = json.loads(line)
            return {
                'source_ip': data.get('source_ip', ''),
                'timestamp': data.get('timestamp', ''),
                'method': data.get('method', ''),
                'path': data.get('path', ''),
                'status': int(data.get('status', 0)),
                'response_size': int(data.get('response_size', 0)),
            }
        except (json.JSONDecodeError, ValueError):
            return None
