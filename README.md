# LogSentry: Brute-force Login Detector

## Overview

LogSentry is a beginner-friendly cybersecurity project developed using Python. It analyses authentication logs to extract login information, identify suspicious login patterns, and generate reports on authentication activity.

The project focuses on log parsing, brute-force detection, password-spraying detection, and basic defensive security analysis.

LogSentry uses generated authentication logs to simulate login activity and demonstrate how simple detection rules can help identify potentially suspicious behaviour.

## Features

- Reads authentication logs line by line.
- Extracts timestamps, usernames, IP addresses, and login statuses using regular expressions.
- Stores valid log entries as dictionaries.
- Counts successful and failed login attempts.
- Identifies and skips malformed log entries without crashing.
- Detects repeated failed login attempts against IP addresses.
- Detects repeated failed login attempts against usernames.
- Identifies potential password-spraying activity by tracking distinct usernames targeted by an IP address.
- Uses configurable failure thresholds and time windows.
- Displays the top five IP addresses and usernames by failed login attempts.
- Generates a summary report of analysed logs.
- Includes automated tests using pytest to verify detection behaviour.

## Detection Rules

LogSentry currently implements two main detection approaches:

### 1. Brute-force Detection

Identifies an IP address or username with five or more failed login attempts within a two-minute window.

### 2. Password-spraying Detection

Identifies an IP address attempting to log in to at least five distinct usernames within a two-minute window.

These rules are configurable and serve as basic detection heuristics. An alert indicates potentially suspicious activity, not confirmation of a successful attack.

## Technologies

- Python
- Regular Expressions (`re`)
- File Handling
- `datetime` and `timedelta`
- `collections.Counter`
- Dictionaries, Lists, and Sets
- pytest

## Project Structure

```text
LogSentry/
├── README.md
├── sample_auth.log
├── logsentry.py
└── test_logsentry.py
```

## Configuration

Detection thresholds and time windows can be adjusted at the beginning of `logsentry.py`.

```python
FAILURE_THRESHOLD = 5
WINDOW_MINUTES = 2

SPRAY_THRESHOLD = 5
SPRAY_WINDOW_MINUTES = 2
```

- `FAILURE_THRESHOLD`: Minimum failed attempts required for brute-force detection.
- `WINDOW_MINUTES`: Time window for brute-force detection.
- `SPRAY_THRESHOLD`: Minimum number of distinct usernames required for password-spraying detection.
- `SPRAY_WINDOW_MINUTES`: Time window for password-spraying detection.

## How to Run

1. Clone or download this repository.
2. Make sure Python is installed.
3. Open the project folder in your terminal.
4. Run:

```bash
python logsentry.py
```

## Running Automated Tests

LogSentry uses pytest to verify its detection logic.

Install pytest if it is not already installed:

```bash
python -m pip install pytest
```

Run the tests:

```bash
python -m pytest
```

The test suite currently contains seven tests covering brute-force detection, username-based detection, password-spraying detection, and multiple detection scenarios.

**Latest test result:** 7 passed.

## Sample Results

The latest test dataset contains 73 log lines:

- 70 valid authentication records.
- 30 successful login attempts.
- 40 failed login attempts.
- 3 malformed entries.

The parser successfully processed all valid records, skipped malformed entries, and generated the expected summary report.

The detection system also successfully identified the simulated brute-force and password-spraying patterns.

## Ethics and Legal Notice

This project uses generated sample logs containing fictional usernames and private IP addresses.

Scanning or attacking systems without ownership or explicit permission is illegal and unethical. All testing and analysis for this project are conducted using generated data or systems that I own or have permission to test.

## Learning Objectives

Through this project, I practised:

- Python file handling and regular expressions.
- Dictionaries, lists, sets, and loops.
- Working with dates and timestamps.
- Counting and analysing authentication events.
- Implementing time-window-based detection logic.
- Understanding brute-force and password-spraying patterns.
- Writing automated tests using pytest.
- Applying basic defensive security concepts.

## Author

**Hanifah Owolabi Yusuf**