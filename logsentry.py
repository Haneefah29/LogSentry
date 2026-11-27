
import re
from datetime import datetime, timedelta
from collections import Counter


FAILURE_THRESHOLD = 5
WINDOW_MINUTES = 2

SPRAY_THRESHOLD = 5
SPRAY_WINDOW_MINUTES = 2


pattern = r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) username=(?P<username>\w+) ip=(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) status=(?P<status>SUCCESS|FAILED)"



def detect_brute_force(parsed_logs, field="ip"):
    failed_by_identifier = {}

    for record in parsed_logs:
        if record["status"] == "FAILED":
            identifier = record[field]

            if identifier not in failed_by_identifier:
                failed_by_identifier[identifier] = []

            failed_by_identifier[identifier].append(
                record["datetime"]
            )

    suspicious_identifiers = []

    window = timedelta(minutes=WINDOW_MINUTES)

    for identifier, timestamps in failed_by_identifier.items():
        timestamps.sort()

        for start in range(len(timestamps)):
            window_start = timestamps[start]
            window_end = window_start + window

            failures_in_window = 0

            for timestamp in timestamps:
                if window_start <= timestamp <= window_end:
                    failures_in_window += 1

            if failures_in_window >= FAILURE_THRESHOLD:
                suspicious_identifiers.append(identifier)
                break

    return suspicious_identifiers


def detect_password_spraying(parsed_logs):
    failed_by_ip = {}

    # Group failed login records by IP
    for record in parsed_logs:
        if record["status"] == "FAILED":
            ip = record["ip"]

            if ip not in failed_by_ip:
                failed_by_ip[ip] = []

            failed_by_ip[ip].append(record)

            suspicious_ips = []

    # Examine each IP separately
    for ip, records in failed_by_ip.items():
        records.sort(key=lambda record: record["datetime"])

        # Examine each record as a possible window start
        for start in range(len(records)):
            window_start = records[start]["datetime"]
            window_end = window_start + timedelta(
                minutes=SPRAY_WINDOW_MINUTES
            )

            usernames = set()

            # Collect distinct usernames within the window
            for record in records:
                if window_start <= record["datetime"] <= window_end:
                    usernames.add(record["username"])

            # Check the password-spraying threshold
            if len(usernames) >= SPRAY_THRESHOLD:
              suspicious_ips.append(ip)
              break

    return suspicious_ips


def main():
    parsed_logs = []

    total_lines = 0
    successful_logins = 0
    failed_logins = 0
    malformed_lines = 0

    with open("sample_auth.log", "r") as file:
        for line in file:
            total_lines += 1
            line = line.strip()

            match = re.search(pattern, line)

            if match:
                record = match.groupdict()

                record["datetime"] = datetime.strptime(
                    record["timestamp"],
                    "%Y-%m-%d %H:%M:%S"
                )

                parsed_logs.append(record)

                if record["status"] == "SUCCESS":
                    successful_logins += 1

                elif record["status"] == "FAILED":
                    failed_logins += 1

            else:
                malformed_lines += 1

    suspicious_ips = detect_brute_force(parsed_logs, field="ip")

    suspicious_usernames = detect_brute_force(parsed_logs, field="username")

    suspicious_spraying_ips = detect_password_spraying(parsed_logs)

    print("\n------ Brute Force Detection ------")

    if suspicious_ips:
        for ip in suspicious_ips:
            print(f"ALERT: {ip} has suspicious login activity")
    else:
        print("No suspicious activity detected.")

        
    
    failed_ips = Counter(
        record["ip"]
        for record in parsed_logs
        if record["status"] == "FAILED"
    )

    print("\n------ Suspicious Username Detection ------")

    if suspicious_usernames:
        for username in suspicious_usernames:
            print(f"ALERT: {username} has suspicious login activity")
    else:
        print("No suspicious usernames detected.")

    print("\n------ Password Spraying Detection ------")

    if suspicious_spraying_ips:
        for ip in suspicious_spraying_ips:
            print(f"ALERT: {ip} may be conducting password spraying")
    else:
        print("No password spraying detected.")

    print("\n------ Top 5 IPs by Failed Logins ------")

    for ip, count in failed_ips.most_common(5):
        print(f"{ip}: {count} failed logins")

    failed_usernames = Counter(
        record["username"]
        for record in parsed_logs
        if record["status"] == "FAILED"
    )

    print("\n------ Top 5 Usernames by Failed Logins ------")

    for username, count in failed_usernames.most_common(5):
        print(f"{username}: {count} failed logins")



    print("\n------ LogSentry Summary Report ------")
    print("Total lines:", total_lines)
    print("Valid records:", len(parsed_logs))
    print("Successful logins:", successful_logins)
    print("Failed logins:", failed_logins)
    print("Malformed lines:", malformed_lines)

    print(
        "Count check:",
        successful_logins + failed_logins == len(parsed_logs)
    )


if __name__ == "__main__":
    main()

