
import re
from datetime import datetime, timedelta


def detect_suspicious_activity(events):
    alerts = []

    # Rule 1: Multiple failed login attempts
    failed_logins = {}

    for event in events:
        description = event["description"].lower()

        if "login failed" in description:
            source_match = re.search(
                r"Source:\s*([^\s]+)",
                event["description"]
            )

            source_ip = source_match.group(1) if source_match else "Unknown"
            key = (event["host"], source_ip)

            failed_logins.setdefault(key, []).append(event)

    for (host, source_ip), attempts in failed_logins.items():
        if len(attempts) >= 2:
            alerts.append({
                "rule": "Multiple Failed Login Attempts",
                "severity": "HIGH",
                "host": host,
                "details": (
                    f"{len(attempts)} failed login attempts "
                    f"from {source_ip}"
                )
            })

    # Rule 2: Successful login after failed attempts
    for event in events:
        if "login successful" not in event["description"].lower():
            continue

        source_match = re.search(
            r"Source:\s*([^\s]+)",
            event["description"]
        )

        if not source_match:
            continue

        source_ip = source_match.group(1)

        for previous in events:
            if "login failed" not in previous["description"].lower():
                continue

            previous_source = re.search(
                r"Source:\s*([^\s]+)",
                previous["description"]
            )

            if (
                previous_source
                and previous_source.group(1) == source_ip
                and previous["host"] == event["host"]
                and previous["timestamp"] < event["timestamp"]
            ):
                alerts.append({
                    "rule": "Successful Login After Failed Attempts",
                    "severity": "HIGH",
                    "host": event["host"],
                    "details": (
                        f"Successful login from {source_ip} "
                        "after previous failed attempts"
                    )
                })
                break

    # Rule 3: Suspicious PowerShell execution
    for event in events:
        if "suspicious powershell" in event["description"].lower():
            alerts.append({
                "rule": "Suspicious PowerShell Execution",
                "severity": "HIGH",
                "host": event["host"],
                "details": event["description"]
            })

    # Rule 4: Outbound network activity
    for event in events:
        if "outbound network connection" in event["description"].lower():
            alerts.append({
                "rule": "Outbound Network Activity",
                "severity": "MEDIUM",
                "host": event["host"],
                "details": event["description"]
            })

    return alerts