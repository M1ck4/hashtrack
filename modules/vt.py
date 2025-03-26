import requests
import time
import os
import json
from datetime import datetime
from typing import List, Dict
from . import config as cfg

VT_BASE_URL = "https://www.virustotal.com/api/v3/files/"
CACHE_PATH = os.path.join(".cache", "vt_cache.json")

# Simple ANSI color codes for console coloring
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

class VirusTotal:
    def __init__(self, api_key: str, rate_limit: int = 4, daily_quota: int = 500):
        """
        :param api_key: VirusTotal API key
        :param rate_limit: Max requests per minute
        :param daily_quota: Max requests per day (resets at midnight)
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.daily_quota = daily_quota

        # Track usage in the current day
        self.requests_made = 0
        self.last_request_time = 0

        # Load local cache (including daily quota info)
        self.cache = self._load_cache()
        self._init_quota_state()

    def _load_cache(self) -> Dict:
        """Loads the VirusTotal cache from disk, returning an empty dict if missing or invalid."""
        if os.path.exists(CACHE_PATH):
            try:
                with open(CACHE_PATH, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache(self):
        """Persists the in-memory cache (including quota_info) to disk."""
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, 'w', encoding='utf-8') as f:
            json.dump(self.cache, f, indent=4)

    def _init_quota_state(self):
        """
        Checks if 'quota_info' exists in the cache and if it's for today's date.
        If it's a new day, reset requests_made to 0. Otherwise, continue from cache.
        """
        today_str = datetime.now().strftime("%Y-%m-%d")

        if "quota_info" not in self.cache:
            # Initialize quota_info in the cache
            self.cache["quota_info"] = {
                "date": today_str,
                "requests_made": 0
            }
            self._save_cache()
        else:
            cached_date = self.cache["quota_info"].get("date", "")
            cached_requests = self.cache["quota_info"].get("requests_made", 0)

            if cached_date != today_str:
                # It's a new day
                self.cache["quota_info"]["date"] = today_str
                self.cache["quota_info"]["requests_made"] = 0
                self._save_cache()
            else:
                self.requests_made = cached_requests

    def _respect_rate_limit(self):
        """If the last request was made too recently, sleep to avoid exceeding self.rate_limit."""
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < 60 / self.rate_limit:
            time.sleep((60 / self.rate_limit) - elapsed)
        self.last_request_time = time.time()

    def query_hash(self, file_hash: str, use_cache: bool = True) -> Dict:
        """
        Queries VirusTotal for 'file_hash'. If it's in the local cache (and use_cache=True),
        return the cached result. Otherwise, enforce daily quota & rate limit, query
        VirusTotal, update the cache, and return the result.
        """
        # 1) Check local cache
        if use_cache and file_hash in self.cache:
            return self.cache[file_hash]

        # 2) Verify we have an API key
        if not self.api_key:
            return {"error": "API key not set"}

        # 3) Enforce daily quota
        if self.requests_made >= self.daily_quota:
            return {"error": "Daily quota exceeded"}

        # 4) Respect rate limit
        self._respect_rate_limit()

        # 5) Make the VT request
        headers = {"x-apikey": self.api_key}
        url = VT_BASE_URL + file_hash
        response = requests.get(url, headers=headers)

        # 6) Update usage counters
        self.requests_made += 1
        if "quota_info" in self.cache:
            self.cache["quota_info"]["requests_made"] = self.requests_made
        self._save_cache()

        # 7) Parse the response
        if response.status_code == 200:
            data = response.json()
            result_data = data.get("data", {})
            attributes = result_data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            permalink = result_data.get("links", {}).get("self", "")

            parsed = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "timestamp": datetime.now().isoformat(),
                "permalink": permalink
            }
            self.cache[file_hash] = parsed
            return parsed
        elif response.status_code == 404:
            return {"error": "Not found in VirusTotal"}
        else:
            return {"error": f"VT API error: {response.status_code}"}


def generate_vt_report(
    proc_data: List[Dict],
    vt: VirusTotal,
    output_path: str,
    use_cache: bool = True,
    print_to_console: bool = True
):
    """
    Gathers unique hashes from proc_data, queries them with vt,
    prints immediate real-time results to the console for each hash,
    and writes a text report to output_path at the end.
    Also includes a direct VirusTotal web GUI link for each hash and
    appends a summary of the overall scan results.
    """
    # 1) Build a map of hash -> list of (exe name, path) for reference
    hash_to_paths = {}
    for proc in proc_data:
        h = proc.get('hash')
        if not h:
            continue
        if h not in hash_to_paths:
            hash_to_paths[h] = []
        exe_name = proc.get('name', 'Unknown.exe')
        exe_path = proc.get('path', 'Unknown path')
        hash_to_paths[h].append((exe_name, exe_path))

    # 2) Collect unique hashes & prepare results storage
    unique_hashes = list(hash_to_paths.keys())
    vt_results = {}

    if print_to_console:
        print(f"\n{YELLOW}========== Starting VirusTotal Scanning =========={RESET}")
        print(f"Found {len(unique_hashes)} unique hash{'es' if len(unique_hashes) != 1 else ''}.\n")

    # 3) Query each unique hash & print results immediately
    for index, h in enumerate(unique_hashes, start=1):
        # Compute the GUI link for the hash
        gui_link = f"https://www.virustotal.com/gui/file/{h}"
        
        # Show which hash we're scanning along with its associated .exe info
        if print_to_console:
            print(f"{YELLOW}[{index}/{len(unique_hashes)}]{RESET} Scanning hash: {h}", flush=True)
            for (exe_name, exe_path) in hash_to_paths[h]:
                print(f"  EXE: {exe_name}")
                print(f"  Path: {exe_path}")

        # Actual VT query
        result = vt.query_hash(h, use_cache=use_cache)
        vt_results[h] = result

        if print_to_console:
            if 'error' in result:
                print(f"{RED}  Error: {result['error']}{RESET}\n", flush=True)
            else:
                malicious = result['malicious']
                suspicious = result['suspicious']
                undetected = result['undetected']
                harmless = result['harmless']

                # Color-code for easier triage
                mal_str = f"{RED}{malicious}{RESET}" if malicious > 0 else f"{GREEN}{malicious}{RESET}"
                sus_str = f"{YELLOW}{suspicious}{RESET}" if suspicious > 0 else f"{GREEN}{suspicious}{RESET}"

                print(f"  Malicious: {mal_str}")
                print(f"  Suspicious: {sus_str}")
                print(f"  Undetected: {undetected}")
                print(f"  Harmless: {harmless}")
                print(f"  API Link: {result['permalink']}")
                print(f"  Web Link: {gui_link}\n", flush=True)

    # 4) Write the final text report including individual file results
    with open(output_path, 'w', encoding='utf-8') as report:
        report.write("# VirusTotal Report\n\n")
        for proc in proc_data:
            h = proc.get('hash')
            path = proc.get('path', 'Unknown path')
            exe_name = proc.get('name', 'Unknown.exe')

            report.write(f"File: {path}\n")
            report.write(f"EXE: {exe_name}\n")

            if h:
                final = vt_results.get(h, {"error": "No result found"})
                gui_link = f"https://www.virustotal.com/gui/file/{h}"
                if 'error' in final:
                    report.write(f"  Error: {final['error']}\n\n")
                else:
                    report.write(f"  SHA256: {h}\n")
                    report.write(f"  Malicious: {final['malicious']}\n")
                    report.write(f"  Suspicious: {final['suspicious']}\n")
                    report.write(f"  Undetected: {final['undetected']}\n")
                    report.write(f"  Harmless: {final['harmless']}\n")
                    report.write(f"  Last Checked: {final['timestamp']}\n")
                    report.write(f"  API Link: {final['permalink']}\n")
                    report.write(f"  Web Link: {gui_link}\n\n")
            else:
                report.write("  Error: No hash available\n\n")

        # 5) Compute and write a summary of the overall scan results
        total_hashes = len(unique_hashes)
        malicious_count = 0
        suspicious_count = 0
        undetected_count = 0
        flagged_malicious = []
        flagged_suspicious = []
        for h, result in vt_results.items():
            if 'error' in result:
                continue
            if result['malicious'] > 0:
                malicious_count += 1
                flagged_malicious.append(f"https://www.virustotal.com/gui/file/{h}")
            if result['suspicious'] > 0:
                suspicious_count += 1
                flagged_suspicious.append(f"https://www.virustotal.com/gui/file/{h}")
            if result['malicious'] == 0 and result['suspicious'] == 0:
                undetected_count += 1

        report.write("========== Summary ==========\n")
        report.write(f"Total unique hashes scanned: {total_hashes}\n")
        report.write(f"Undetected: {undetected_count}\n")
        report.write(f"Malicious: {malicious_count}\n")
        report.write(f"Suspicious: {suspicious_count}\n")
        if flagged_malicious:
            report.write("Possible malicious files:\n")
            for link in flagged_malicious:
                report.write(f"  {link}\n")
        if flagged_suspicious:
            report.write("Possible suspicious files:\n")
            for link in flagged_suspicious:
                report.write(f"  {link}\n")
        report.write("\n")

    # 6) Print the summary to the console as well
    if print_to_console:
        print("========== Summary ==========")
        print(f"Total unique hashes scanned: {total_hashes}")
        print(f"Undetected: {undetected_count}")
        print(f"Malicious: {malicious_count}")
        print(f"Suspicious: {suspicious_count}")
        if flagged_malicious:
            print("Possible malicious files:")
            for link in flagged_malicious:
                print(f"  {link}")
        if flagged_suspicious:
            print("Possible suspicious files:")
            for link in flagged_suspicious:
                print(f"  {link}")
        print()

    if print_to_console:
        print(f"{GREEN}Scanning complete. Full report written to: {output_path}{RESET}\n")
