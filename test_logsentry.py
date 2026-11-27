
from datetime import datetime, timedelta

from logsentry import detect_brute_force, detect_password_spraying


def test_detects_brute_force_burst():
    logs = []

    start_time = datetime(2026, 11, 21, 8, 51, 0)

    for minute_offset in [0, 0, 0, 0, 1]:
        timestamp = start_time + timedelta(minutes=minute_offset)

        logs.append({
            "ip": "192.168.1.99",
            "status": "FAILED",
            "datetime": timestamp
        })

    result = detect_brute_force(logs)

    assert "192.168.1.99" in result



def test_does_not_detect_spread_out_failures():
    logs = []

    start_time = datetime(2026, 11, 21, 9, 0, 0)

    for minute_offset in [0, 15, 30, 45, 60]:
        timestamp = start_time + timedelta(minutes=minute_offset)

        logs.append({
            "ip": "192.168.1.200",
            "status": "FAILED",
            "datetime": timestamp
        })

    result = detect_brute_force(logs)

    assert "192.168.1.200" not in result


def test_detects_brute_force_against_username():
    logs = []

    start_time = datetime(2026, 11, 21, 10, 0, 0)

    for minute_offset in [0, 0, 0, 0, 1]:
        timestamp = start_time + timedelta(minutes=minute_offset)

        logs.append({
            "ip": f"192.168.1.{10 + len(logs)}",
            "username": "amina",
            "status": "FAILED",
            "datetime": timestamp
        })

    result = detect_brute_force(logs, field="username")

    assert "amina" in result


def test_does_not_detect_below_threshold():
    logs = []
    start_time = datetime(2026, 11, 21, 11, 0, 0)

    for minute_offset in [0, 0, 0, 1]:
        timestamp = start_time + timedelta(minutes=minute_offset)
        logs.append({
            "ip": "192.168.1.50",
            "status": "FAILED",
            "datetime": timestamp
        })

    result = detect_brute_force(logs)

    assert "192.168.1.50" not in result


def test_detects_password_spraying():
    logs = []
    start_time = datetime(2026, 11, 21, 12, 0, 0)

    usernames = ["amina", "umar", "maryam", "bilal", "zainab"]

    for minute_offset, username in enumerate(usernames):
        timestamp = start_time + timedelta(seconds=minute_offset * 20)

        logs.append({
            "ip": "192.168.1.80",
            "username": username,
            "status": "FAILED",
            "datetime": timestamp
        })

    result = detect_password_spraying(logs)

    assert "192.168.1.80" in result


def test_does_not_detect_repeated_attempts_against_one_username():
    logs = []
    start_time = datetime(2026, 11, 21, 13, 0, 0)

    for second_offset in [0, 20, 40, 60, 80]:
        timestamp = start_time + timedelta(seconds=second_offset)

        logs.append({
            "ip": "192.168.1.90",
            "username": "amina",
            "status": "FAILED",
            "datetime": timestamp
        })

    result = detect_password_spraying(logs)

    assert "192.168.1.90" not in result


def test_detects_multiple_password_spraying_ips():
    logs = []
    start_time = datetime(2026, 11, 21, 14, 0, 0)

    usernames = ["amina", "umar", "maryam", "bilal", "zainab"]
    ips = ["192.168.1.80", "192.168.1.81"]

    for ip in ips:
        for second_offset, username in enumerate(usernames):
            timestamp = start_time + timedelta(seconds=second_offset * 20)

            logs.append({
                "ip": ip,
                "username": username,
                "status": "FAILED",
                "datetime": timestamp
            })

    result = detect_password_spraying(logs)

    assert "192.168.1.80" in result
    assert "192.168.1.81" in result
    assert len(result) == 2
