# LogSentry: Brute-force Login Detector

## Overview

LogSentry is a beginner-friendly cybersecurity project developed using Python. It reads and analyses authentication logs to extract login information and generate a summary of login activity.

This project is the first stage of my cybersecurity learning journey, focusing on log parsing and basic defensive security analysis.

## Features

- Reads authentication logs line by line.
- Extracts timestamps, usernames, IP addresses and login statuses using regular expressions.
- Stores valid log entries as dictionaries in a list.
- Counts successful and failed login attempts.
- Detects, counts and skips malformed log entries without crashing.
- Generates a summary report of the analysed logs.

## Technologies

- Python
- Regular Expressions (`re`)
- File Handling

## Project Structure

```text
LogSentry/
├── README.md
├── sample_auth.log
└── logsentry.py
```

## How to Run

1. Clone or download this repository.
2. Make sure Python is installed.
3. Open the project folder in your terminal.
4. Run:

```bash
python logsentry.py
```

## Sample Results

The parser was tested with 63 log lines:

- 60 valid authentication records
- 30 successful login attempts
- 30 failed login attempts
- 3 malformed entries

All valid records were parsed successfully, and malformed entries were skipped without crashing the program.
I verified the valid login counts by excluding the two malformed entries that contain status fields.

## Ethics and Legal Notice

This project uses generated sample logs containing fictional usernames and private IP addresses.

Scanning or attacking systems without ownership or explicit permission is illegal and unethical. All testing and analysis for this project are conducted using generated data or systems that I own or have permission to test.

## Learning Objectives
Through this project, I practised Python file handling, regular expressions, dictionaries, lists, loops, conditional statements and basic log analysis.

## Author
Hanifah Owolabi Yusuf