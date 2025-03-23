# HashTrack 1.0

![Python 3.6+](https://img.shields.io/badge/python-3.6%2B-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-brightgreen.svg)

**HashTrack** is a modular command‐line utility for enumerating running processes, computing SHA256 hashes of executables, optionally checking them against VirusTotal, exporting scan results, and (on Windows) validating digital signatures. It is designed to be lightweight yet flexible, providing a clear view of process metadata and threat intelligence lookups in one place.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Commands](#basic-commands)
  - [Exporting Results](#exporting-results)
  - [VirusTotal Integration](#virustotal-integration)
  - [Digital Signature Checks](#digital-signature-checks)
- [Configuration](#configuration)
- [Logging and Cleanup](#logging-and-cleanup)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

- **Process Enumeration:** Scan system or user‐level processes, choosing `--all` or `--user`.
- **SHA256 Hashing:** Generate unique fingerprints for each `.exe`.
- **Export Options:** Write results to JSON/CSV for documentation or further analysis.
- **VirusTotal Lookups:** Cache results to avoid re-checking the same hash and hitting free-tier limits.
- **Signature Verification (Windows):** Runs PowerShell’s `Get-AuthenticodeSignature` for Authenticode details.
- **Automatic Log Cleanup:** Remove stale logs after a configurable number of days.

## Requirements

- **Python 3.6+**
- **Packages:**  
  - `psutil` (for process enumeration)  
  - `requests` (for VirusTotal API calls)
- (Optional) **PowerShell** on Windows if using `--check-signatures`.

## Installation

1. **Clone** or download this repository.  
2. **Install dependencies**:
    
        pip install psutil requests

3. **(Optional)** Provide a VirusTotal API key in `config.ini` if using `--vt`.

## Usage

Run the main script with various flags to control the output and behavior:

    python hashtrack.py [OPTIONS]

### Basic Commands

- **`--all`**: Include all processes (both user and system).  
- **`--user`**: Only include user‐level processes (skip system ones).  
- **`--minimal`**: Print only path + hash.  
- **`--verbose`**: Show extended details (CPU usage, memory usage, parent name, etc.).

### Exporting Results

- **`--export`**: Write results to JSON in a date‐stamped folder under `logs/`.  
- **`--csv`**: Also produce a CSV with the same data.  
- **`--keep-days X`**: Remove logs older than `X` days at the end of each run.

### VirusTotal Integration

- **`--vt`**: Check each unique SHA256 against VirusTotal.  
  - Requires `api_key` in `config.ini`.  
  - Caches responses to `.cache/vt_cache.json` by default if `use_cache = yes`.  
- **`--vt-no-cache`**: Force new lookups, ignoring the local cache.

### Digital Signature Checks

- **`--check-signatures`**: (Windows only) Use PowerShell’s `Get-AuthenticodeSignature` to examine `.exe` certificates.  
  - Outputs status (e.g. `Valid`, `NotSigned`, or integer status codes) plus the issuer and subject info, if present.

## Configuration

The `config.ini` file in the same folder defines defaults:

    [virustotal]
    api_key = YOUR_API_KEY
    rate_limit_per_min = 4
    daily_quota = 500
    use_cache = yes
    cache_expiry_days = 7

    [output]
    default_folder = logs
    keep_days = 7

    [options]
    quiet_default = no

- **`api_key`**: Your VirusTotal API key.  
- **`rate_limit_per_min`**, **`daily_quota`**: The script respects these limits for free-tier usage.  
- **`use_cache`**: Set to `yes` if you want to cache VirusTotal results.  
- **`keep_days`**: Default days to keep logs.  
- **`quiet_default`**: If set to `yes`, the script runs in quiet mode unless overridden by `--quiet`.

## Logging and Cleanup

- Exports and logs go into `logs/<YYYY-MM-DD>` automatically.  
- **`--keep-days X`** removes older logs.  
- The `.cache/vt_cache.json` is where VirusTotal responses are stored.

## Troubleshooting

- **No API Key:** If you run `--vt` without specifying your key in `config.ini`, the script will skip VirusTotal checks.  
- **Signature Status = 0:** Some Windows/PowerShell versions return numeric codes for signature checks. The script attempts to parse these plus any message string.  
- **Permission Errors:** If certain system processes are unreadable, run in an elevated (admin) terminal on Windows.

## License

This project is licensed under the **MIT License**.  
