import re
import sys
from collections import Counter, defaultdict

LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else "logs/otp_security.log"

APP_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - "
    r"(?P<level>\w+) - (?P<msg>.*)$"
)
ACCESS_LINE = re.compile(
    r'^(?P<ip>\S+) - - \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>\S+) HTTP/[\d.]+" (?P<status>\d+)'
)
IP_IN_MSG = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

status_counts = Counter()
path_counts = Counter()
ip_requests = Counter()
ip_statuses = defaultdict(Counter)
level_counts = Counter()
lockout_events = []
ratelimit_events = []
failed_attempts = defaultdict(int)

with open(LOG_FILE) as f:
    for line in f:
        line = line.rstrip("\n")

        m = ACCESS_LINE.match(line)
        if m:
            ip = m.group("ip")
            status = m.group("status")
            path = m.group("path")
            status_counts[status] += 1
            path_counts[path] += 1
            ip_requests[ip] += 1
            ip_statuses[ip][status] += 1
            continue

        m = APP_LINE.match(line)
        if m:
            level = m.group("level")
            msg = m.group("msg")
            level_counts[level] += 1

            ip_match = IP_IN_MSG.search(msg)
            if ip_match is None:
                # Generic module-level line with no IP attached (e.g. from
                # otp_generator.py itself) — the matching app.py line that
                # names the source IP covers the same event, so skip here.
                continue
            ip = ip_match.group(1)
            msg_l = msg.lower()

            if "locked after" in msg_l:
                lockout_events.append((m.group("ts"), ip, msg))
            if "rate limit exceeded" in msg_l or "generation blocked" in msg_l:
                ratelimit_events.append((m.group("ts"), ip, msg))
            if "incorrect otp" in msg_l or ("failed" in msg_l and "attempt" in msg_l):
                failed_attempts[ip] += 1


def dedupe(events):
    """Collapse events from the same IP with the same message within the
    same second, which happen when a request triggers two log calls."""
    seen = set()
    out = []
    for ts, ip, msg in events:
        key = (ts.split(",")[0], ip, msg)
        if key not in seen:
            seen.add(key)
            out.append((ts, ip, msg))
    return out


lockout_events = dedupe(lockout_events)
ratelimit_events = dedupe(ratelimit_events)

print("=" * 60)
print("OTP SECURITY LOG ANALYSIS")
print("=" * 60)

print("\n-- HTTP status code summary --")
for status, count in sorted(status_counts.items()):
    print(f"  {status}: {count} requests")

print("\n-- Requests by endpoint --")
for path, count in path_counts.most_common():
    print(f"  {path}: {count}")

print("\n-- Requests by source IP --")
for ip, count in ip_requests.most_common():
    breakdown = ", ".join(f"{s}:{c}" for s, c in ip_statuses[ip].items())
    print(f"  {ip}: {count} total  ({breakdown})")

print("\n-- Log level summary --")
for level, count in level_counts.most_common():
    print(f"  {level}: {count}")

print("\n-- Failed OTP attempts by source IP --")
if failed_attempts:
    for ip, count in failed_attempts.items():
        print(f"  {ip}: {count} failed attempt(s)")
else:
    print("  None recorded")

print("\n-- Lockout events (possible brute-force) --")
if lockout_events:
    for ts, ip, msg in lockout_events:
        print(f"  [{ts}] {ip}: {msg}")
else:
    print("  None recorded")

print("\n-- Rate-limit events (possible flooding) --")
if ratelimit_events:
    for ts, ip, msg in ratelimit_events:
        print(f"  [{ts}] {ip}: {msg}")
else:
    print("  None recorded")

print("\n" + "=" * 60)
flagged_ips = set(failed_attempts) | {ip for _, ip, _ in lockout_events} | {ip for _, ip, _ in ratelimit_events}
if flagged_ips:
    print(f"FLAGGED SOURCE IPs: {', '.join(sorted(flagged_ips))}")
else:
    print("No IPs flagged for suspicious activity.")
print("=" * 60)
