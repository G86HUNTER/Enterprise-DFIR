
import re
from datetime import datetime


TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

EVENT_RULES = [
    {
        "keyword": "login failed",
        "category": "Authentication",
        "severity": "MEDIUM"
    },
    {
        "keyword": "login successful",
        "category": "Authentication",
        "severity": "INFO"
    },
    {
        "keyword": "suspicious powershell",
        "category": "Process Execution",
        "severity": "HIGH"
    },
    {
        "keyword": "outbound network connection",
        "category": "Network Activity",
        "severity": "MEDIUM"
    }
]


def parse_log_lines(lines):
    events = []

    for line_number, line in enumerate(lines, start=1):
        line = line.strip()

        if not line:
            continue

        match = re.match(
            r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+-\s+(.*)$",
            line
        )

        if not match:
            continue

        timestamp_text, description = match.groups()

        try:
            timestamp = datetime.strptime(
                timestamp_text, TIMESTAMP_FORMAT
            )
        except ValueError:
            continue

        category = "General Activity"
        severity = "INFO"

        for rule in EVENT_RULES:
            if rule["keyword"] in description.lower():
                category = rule["category"]
                severity = rule["severity"]
                break

        host_match = re.search(r"Host:\s*([^\s]+)", description)
        source_match = re.search(r"Source:\s*([^\s]+)", description)
        destination_match = re.search(
            r"Destination:\s*([^\s]+)", description
        )

        events.append({
            "timestamp": timestamp,
            "description": description,
            "category": category,
            "severity": severity,
            "host": host_match.group(1) if host_match else None,
            "source": source_match.group(1) if source_match else None,
            "destination": (
                destination_match.group(1)
                if destination_match else None
            ),
            "source_line": line,
            "line_number": line_number
        })

    return sorted(events, key=lambda event: event["timestamp"])


def parse_log_file(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return parse_log_lines(file.readlines())
