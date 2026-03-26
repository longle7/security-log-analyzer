# SecurityLogAnalyzer
SecurityLogAnalyzer is a C# .NET console app that scans 1 million login events and detects potential brute-force attacks based on failed login patterns.

## Features

- Reads `logs.json` with 1,000,000 synthetic login events.
- Filters failed login attempts and groups them by IP address.
- Uses a sliding time window to find IPs with 10+ failed logins within 60 minutes.
- Writes human-readable alerts to `alerts.csv`.

## How it works

The core analysis is in `Analyzer.cs`:

- Deserialize JSON logs into `LogEntry` objects.
- Group failed logins by IP and sort each IP’s events by timestamp.
- For each IP, slide a 10-event window and check if the time span is ≤ 60 minutes.
- If so, emit an alert like:  
  `ALERT: Brute-force on 192.168.1.42: 10+ fails in 12:34`

On my machine, it processes 1,000,000 logs in about **1.3 seconds**.

## Getting started

Prerequisites:

- .NET SDK (7.0 or later) installed.

Clone and run:

```bash
git clone https://github.com/longle7/security-log-analyzer.git
cd security-log-analyzer
dotnet run --project SecurityLogAnalyzer
```

After it runs, check:

- Console output for the number of alerts.
- `alerts.csv` in the project folder for the full list of alerts.

## Project motivation

This project was built to practice:

- Efficient data processing in C# with .NET.
- Working with JSON, collections, and LINQ.
- Implementing a classic “sliding window” algorithm on timestamped data.