import argparse
import time
import os

from modules import scanner, exporter, cleanup, config as cfg
from modules.vt import VirusTotal, generate_vt_report

# ANSI color codes for simple console coloring
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Load configuration
config = cfg.load_config()
DEFAULT_FOLDER = cfg.get_output_folder(config)
DEFAULT_KEEP_DAYS = cfg.get_keep_days(config)
DEFAULT_QUIET = cfg.quiet_mode_default(config)
VT_API_KEY = cfg.get_vt_api_key(config)
VT_RATE_LIMIT = cfg.get_vt_rate_limit(config)
VT_DAILY_QUOTA = cfg.get_vt_daily_quota(config)
VT_USE_CACHE = cfg.get_vt_use_cache(config)

def print_vt_result(h, result):
    gui_link = f"https://www.virustotal.com/gui/file/{h}"
    if 'error' in result:
        print(f"{RED}  [!] Error: {result['error']}{RESET}")
    else:
        mal = result['malicious']
        sus = result['suspicious']
        und = result['undetected']
        harmless = result['harmless']
        print(f"  Malicious: {RED}{mal}{RESET}" if mal else f"  Malicious: {GREEN}{mal}{RESET}")
        print(f"  Suspicious: {YELLOW}{sus}{RESET}" if sus else f"  Suspicious: {GREEN}{sus}{RESET}")
        print(f"  Undetected: {und}")
        print(f"  Harmless: {harmless}")
        print(f"  Web Link: {gui_link}\n")

def main():
    parser = argparse.ArgumentParser(
        prog="hashtrack",
        description="""
HashTrack - A modular process hashing & logging tool.

Scans running processes, computes SHA256 hashes, or checks a specific file/hash.
Optionally:
 - Exports results to JSON or CSV
 - Compares a computed hash to an expected value (--compare)
 - Checks a hash against VirusTotal (--vt)
 - Performs Authenticode signature checks (Windows only)
        """,
        epilog="""
EXAMPLES:
  1) hashtrack --all --verbose
     Include all processes, showing extended details (CPU usage, memory usage, parent, etc.).

  2) hashtrack --vt
     Query all unique hashes against VirusTotal. Requires an API key in config.ini.

  3) hashtrack --user --export
     Only user-level processes, export results to JSON in logs/<date>/.

  4) hashtrack --check-signatures
     (Windows only) Calls PowerShell to check Authenticode signatures.

  5) hashtrack --hashcheck suspicious.exe
     Computes SHA256 of the specified file and prints it.

  6) hashtrack --hashcheck suspicious.exe --compare a1b2c3d4...
     Computes the hash and compares it to the provided expected hash.

  7) hashtrack --hashcheck 8c7aaf3ea1fae2f38... --vt
     Checks a provided hash directly against VirusTotal.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Existing options
    parser.add_argument('--all', action='store_true',
                        help='Include all processes (user + system). Overrides --user if both are used.')
    parser.add_argument('--user', action='store_true',
                        help='Only include user-level processes (skips system processes).')
    parser.add_argument('--minimal', action='store_true',
                        help='Minimal console output (just path + hash).')
    parser.add_argument('--verbose', action='store_true',
                        help='Extended console output (CPU usage, memory usage, parent name, etc.).')
    parser.add_argument('--export', action='store_true',
                        help='Export scan results to a JSON file in logs/<date>/.')
    parser.add_argument('--csv', action='store_true',
                        help='Also export results to a CSV file.')
    parser.add_argument('--vt', action='store_true',
                        help='Check all unique hashes against VirusTotal. Requires an API key in config.ini.')
    parser.add_argument('--vt-no-cache', action='store_true',
                        help='Force a fresh VT lookup for each hash, ignoring the local cache.')
    parser.add_argument('--check-signatures', action='store_true',
                        help='(Windows only) Check Authenticode signatures via PowerShell.')
    parser.add_argument('--keep-days', type=int,
                        help='Delete logs older than X days (default = 7 or config.ini).')
    parser.add_argument('--quiet', action='store_true',
                        help='Suppress most console output (except the final timing message).')
    # New hashcheck options
    parser.add_argument('--hashcheck', type=str,
                        help='Check a specific file or raw SHA256 hash. If a file path is provided, its hash is computed.')
    parser.add_argument('--compare', type=str,
                        help='Optional. Compare the computed hash to this expected value.')

    args = parser.parse_args()

    # HashCheck mode: if --hashcheck is provided, process the single file/hash and exit early.
    if args.hashcheck:
        input_val = args.hashcheck
        # Initialize VirusTotal instance if needed
        vt = None
        if args.vt:
            vt = VirusTotal(VT_API_KEY, VT_RATE_LIMIT, VT_DAILY_QUOTA)
        # If input is a valid file path, compute its hash; otherwise, assume it's a raw hash.
        if os.path.isfile(input_val):
            computed_hash = scanner.hash_file(input_val)
            print(f"\n[+] File: {input_val}")
            print(f"    SHA256: {computed_hash}")
            if args.compare:
                print(f"    Expected: {args.compare}")
                if args.compare.lower() == computed_hash.lower():
                    print(f"{GREEN}[✓] Match: File hash matches expected hash.{RESET}")
                else:
                    print(f"{RED}[✗] Mismatch: File hash does NOT match expected hash.{RESET}")
            if args.vt:
                if not VT_API_KEY:
                    print(f"{RED}[!] VirusTotal API key not set. Skipping VT check.{RESET}")
                else:
                    result = vt.query_hash(computed_hash, use_cache=(VT_USE_CACHE and not args.vt_no_cache))
                    print_vt_result(computed_hash, result)
        else:
            # Assume the input is a raw hash string.
            raw_hash = input_val
            print(f"\n[+] Using provided hash: {raw_hash}")
            if args.compare:
                if args.compare.lower() == raw_hash.lower():
                    print(f"{GREEN}[✓] Provided hash matches expected hash.{RESET}")
                else:
                    print(f"{RED}[✗] Provided hash does NOT match expected hash.{RESET}")
            if args.vt:
                if not VT_API_KEY:
                    print(f"{RED}[!] VirusTotal API key not set. Skipping VT check.{RESET}")
                else:
                    result = vt.query_hash(raw_hash, use_cache=(VT_USE_CACHE and not args.vt_no_cache))
                    print_vt_result(raw_hash, result)
        return  # Exit early after processing hashcheck

    # If --all is set, override --user
    if args.all and args.user:
        print(f"{YELLOW}⚠️ Note: --all flag overrides --user. Ignoring --user.{RESET}")
        args.user = False

    quiet_mode = args.quiet or DEFAULT_QUIET

    # If using VirusTotal, let the user know (unless quiet)
    if args.vt and not quiet_mode:
        if not VT_API_KEY:
            print(f"{RED}[!] VirusTotal API key not set. Skipping VT checks.{RESET}")
        else:
            print(f"{GREEN}[+] VirusTotal checks enabled. Using the provided API key.{RESET}")

    # Gather process info
    proc_data = scanner.get_process_info(
        minimal=args.minimal,
        user_only=args.user,
        all_processes=args.all,
        verbose=args.verbose,
        check_signatures=args.check_signatures
    )

    if not quiet_mode:
        print(f"\n🔍 Found {len(proc_data)} process{'es' if len(proc_data) != 1 else ''}.")

        for proc in proc_data:
            if args.minimal:
                # Minimal: path + hash
                print(f"{proc['path']}\n  ↳ {proc['hash']}\n")
            else:
                # Normal or verbose mode
                pid_str = f"[PID: {proc['pid']}]" if 'pid' in proc else ""
                name_str = proc.get('name', 'Unknown')
                print(f"{pid_str} {name_str}")
                if 'path' in proc:
                    print(f"  Path: {proc['path']}")
                if 'hash' in proc:
                    print(f"  SHA256: {proc['hash']}")

                # Verbose extras
                if args.verbose:
                    print(f"  Username: {proc.get('username')}")
                    print(f"  Parent PID: {proc.get('ppid')}")
                    if 'parent_name' in proc:
                        print(f"  Parent Name: {proc.get('parent_name')}")
                    if 'created' in proc:
                        print(f"  Created (epoch): {proc.get('created')}")
                    if 'cpu_percent' in proc:
                        print(f"  CPU usage: {proc.get('cpu_percent')}")
                    if 'memory_percent' in proc:
                        print(f"  Memory usage: {proc.get('memory_percent')}")

                # Signature info if available
                if args.check_signatures and 'signature' in proc:
                    sig_info = proc['signature']
                    sig_status = sig_info.get('status', 'Unknown')
                    print(f"  Signature Status: {sig_status}")
                    issuer = sig_info.get('issuer')
                    subject = sig_info.get('subject')
                    if issuer:
                        print(f"  Issuer: {issuer}")
                    if subject:
                        print(f"  Subject: {subject}")

                print()

    # Export / CSV / VirusTotal for full process scan
    output_folder = None
    base_name = None

    if args.export or args.csv or args.vt:
        output_folder = exporter.ensure_output_folder(DEFAULT_FOLDER)
        base_name = exporter.generate_filename()

    # Write JSON if requested
    if args.export:
        json_file = exporter.write_json(proc_data, output_folder, base_name)
        if not quiet_mode:
            print(f"✅ JSON saved to: {json_file}")

    # Write CSV if requested
    if args.csv:
        csv_file = exporter.write_csv(proc_data, output_folder, base_name.replace('.json', '.csv'))
        if not quiet_mode:
            print(f"✅ CSV saved to: {csv_file}")

    # VirusTotal checks for full scan
    if args.vt and VT_API_KEY:
        vt = VirusTotal(VT_API_KEY, VT_RATE_LIMIT, VT_DAILY_QUOTA)
        vt_report_path = os.path.join(output_folder, f"virustotal_report_{base_name.replace('.json', '.txt')}")
        use_cache = (VT_USE_CACHE and not args.vt_no_cache)

        # Print results to console if not quiet
        generate_vt_report(
            proc_data,
            vt,
            vt_report_path,
            use_cache=use_cache,
            print_to_console=not quiet_mode
        )

    # Cleanup old logs
    keep_days = args.keep_days if args.keep_days is not None else DEFAULT_KEEP_DAYS
    cleanup.cleanup_logs(DEFAULT_FOLDER, keep_days)

if __name__ == '__main__':
    start = time.time()
    main()
    end = time.time()
    print(f"\n🕒 Completed in {end - start:.2f} seconds.")
