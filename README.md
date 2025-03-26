# HashTrack 1.0

![Python 3.6+](https://img.shields.io/badge/python-3.6%2B-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-brightgreen.svg)

**HashTrack** is a modular command-line utility designed for detailed process inspection, malware analysis, and system observability. It enables the identification of running executables, computes SHA256 cryptographic hashes, optionally verifies digital signatures on Windows systems, and queries VirusTotal for threat intelligence all in a lightweight and configurable manner. It is intended for professionals who need detailed, structured insight into what is running on a system and how to assess its legitimacy.

---

## Overview

HashTrack provides an organized and automated method to analyze active processes on your machine. It captures metadata about each process, including the executable path, associated user, process IDs, parent process relationships, and more. It calculates a SHA256 hash of the executable binary, which serves as a unique identifier for checking against external threat databases like VirusTotal.

Beyond simple enumeration, HashTrack can export results to structured files (JSON and CSV), allowing integration with logging systems or forensic archives. If run on Windows, it can also perform Authenticode signature checks using PowerShell, offering insight into whether a file is signed, valid, and trusted.

The tool is intended for:
- Threat detection and investigation
- Digital forensics and incident response (DFIR)
- Baseline process analysis in secure environments
- Reverse engineering support
- Audit trail creation for security reviews

---

## Features

**Process Enumeration**  
HashTrack scans all currently running processes using the `psutil` library. It captures various details per process, such as:
- Executable path
- Username under which the process is running
- PID and PPID (parent process ID)
- Creation time
- CPU and memory usage (if verbose mode is enabled)

This comprehensive view enables identification of unusual or unexpected processes that may be signs of compromise or misconfiguration.

**SHA256 Hashing**  
Every executable is hashed using the SHA256 algorithm. This cryptographic fingerprint can be used to:
- Check for known malware via VirusTotal
- Identify if a binary has changed or been tampered with
- Compare processes across systems or time snapshots

**VirusTotal Integration**  
HashTrack can query VirusTotal for any unique hash it computes. If the hash is known to VirusTotal, the tool will retrieve a summary of detections, including counts for malicious, suspicious, harmless, and undetected verdicts. 

To manage usage effectively, it includes a local caching mechanism to avoid redundant queries and respects both rate limits and daily quotas. This makes it viable even on the free-tier of the VirusTotal API.

**Signature Verification**  
On Windows, HashTrack invokes PowerShell to check digital signatures using the `Get-AuthenticodeSignature` command. It reports:
- Status (e.g., Valid, NotSigned, or an error code)
- Certificate issuer and subject
- Validity period (from/to dates)

This feature helps determine whether the executable comes from a trusted source or has been unsigned or altered.

**Exporting and Logging**  
All results can be exported to timestamped folders in both JSON and CSV formats. This makes it easy to archive results, track changes over time, or load into external tools for further analysis. Logs are stored by default under the `logs/YYYY-MM-DD/` directory structure.

**Log Cleanup**  
To prevent long-term clutter, HashTrack automatically removes old log folders after a configurable number of days. This setting is managed through the config file or via command-line overrides.

---

## Requirements

- Python 3.6 or higher
- Dependencies:
  - `psutil` for process enumeration
  - `requests` for VirusTotal API access
- (Windows only) PowerShell for signature verification

Install dependencies with:

```bash
pip install psutil requests
```

---

## Installation

1. Clone or download the repository.
2. Install the required dependencies.
3. (Optional) Edit `config.ini` and insert your VirusTotal API key if you plan to use the `--vt` feature.

---

## Basic Use

To use HashTrack with its default behavior, simply run:

```bash
python hashtrack.py
```

This performs a default scan of system level processes, computing SHA256 hashes and printing standard metadata for each. It does not require any additional arguments to function.

To get help and view all available options:

```bash
python hashtrack.py --help
```

or

```bash
python hashtrack.py -h
```

The help text will show all supported flags, including those for exporting, querying VirusTotal, checking signatures, filtering process types, and adjusting verbosity.

---

## Configuration

HashTrack uses a `config.ini` file to manage persistent settings. If this file does not exist, it will be auto-generated with defaults on first run.

Example structure:

```ini
[virustotal]
api_key = your_api_key_here
rate_limit_per_min = 4
daily_quota = 500
use_cache = yes
cache_expiry_days = 7

[output]
default_folder = logs
keep_days = 7

[options]
quiet_default = no
```

Settings control VirusTotal usage, log retention, console verbosity, and caching behavior.

---

## Logging and Output

When exporting is enabled, scan results are saved to a structured folder:

```
logs/2025-03-26/hashtrack_15-02-18.json
```

Logs older than a defined number of days (default: 7) will be removed automatically unless otherwise specified in `config.ini` or via the `--keep-days` argument.

VirusTotal results, if retrieved, are cached to:

```
.cache/vt_cache.json
```

This cache avoids re-querying the same hashes repeatedly, helping you stay within API limits.

---

## Troubleshooting

**Issue: No API Key Set**  
If you attempt to use `--vt` but the `api_key` in `config.ini` is blank or missing, VirusTotal lookups will be silently skipped. A warning will be printed in the console unless quiet mode is enabled.

**Issue: Permission Denied / Missing Processes**  
On certain systems, especially Windows, some system processes may not be accessible without elevated privileges. Run the terminal or command prompt as Administrator to gain full access to process metadata.

**Issue: Signature Check Fails**  
Digital signature checks require PowerShell and only work on Windows. If you're on Linux or macOS, or if PowerShell is not in your system PATH, this feature will be unavailable. You may also encounter signature errors if the file is unsigned or the certificate is expired.

**Issue: Hash Missing or Null**  
If a file cannot be read (locked, deleted mid-scan, or permission denied), no hash will be produced for that process. This is expected behavior.

**Issue: VirusTotal Quota Exceeded**  
The free API tier has a daily quota (default: 500). If this is exceeded, VirusTotal responses will return error messages. Enable caching to avoid redundant calls and preserve your quota.

**Issue: Logs Not Saving**  
Ensure the script has write permissions in the current working directory or the designated log directory. If `logs/` cannot be created, no output files will be generated.

---

## License

HashTrack is licensed under the MIT License. Use, modify, and distribute with attribution.

