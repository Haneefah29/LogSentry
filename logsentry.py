with open("sample_auth.log", "r") as file:
    for line in file:
        print(line.strip())





import re

pattern = r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) username=(?P<username>\w+) ip=(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) status=(?P<status>SUCCESS|FAILED)"

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
            parsed_logs.append(record)

            if record["status"] == "SUCCESS":
                successful_logins += 1
            elif record["status"] == "FAILED":
                failed_logins += 1

        else:
            malformed_lines += 1

print("\n------ LogSentry Summary Report ------")
print("Total lines:", total_lines)
print("Valid records:", len(parsed_logs))
print("Successful logins:", successful_logins)
print("Failed logins:", failed_logins)
print("Malformed lines:", malformed_lines)

print("Count check:", successful_logins + failed_logins == len(parsed_logs))