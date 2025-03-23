import psutil
import hashlib
import os
import subprocess
from typing import List, Dict, Optional

def hash_file(path: str) -> Optional[str]:
    """
    Returns the SHA256 hash of the file at the given path.
    Returns None if the file is inaccessible or unreadable.
    """
    try:
        with open(path, "rb") as f:
            sha256 = hashlib.sha256()
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
            return sha256.hexdigest()
    except Exception:
        return None

def check_signature(file_path: str) -> Dict[str, Optional[str]]:
    """
    Uses PowerShell's Get-AuthenticodeSignature to check the digital signature of 'file_path'.
    In some environments, 'Status' is an integer code (0=Valid, 1=Invalid, etc.),
    and 'StatusMessage' might contain the human-readable description.

    Returns a dict, for example:
      {
        "status": "0 (Signature is valid)",
        "issuer": "...",
        "subject": "...",
        "valid_from": "...",
        "valid_to": "..."
      }

    NOTE: This approach only works on Windows with PowerShell installed.
    """
    result = {
        "status": "Unknown",
        "issuer": None,
        "subject": None,
        "valid_from": None,
        "valid_to": None
    }
    try:
        # Build the PowerShell command
        cmd = [
            "powershell.exe",
            "-ExecutionPolicy", "Bypass",
            "-NoProfile",
            "Get-AuthenticodeSignature",
            f"'{file_path}'",
            "| ConvertTo-Json"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        if proc.returncode != 0 or not proc.stdout.strip():
            # Possibly not signed or can't be checked
            err_msg = proc.stderr.strip() or "No data"
            result["status"] = f"Error/No data: {err_msg}"
            return result

        import json
        ps_data = json.loads(proc.stdout)

        # If there's a list, take the first item
        if isinstance(ps_data, list) and len(ps_data) > 0:
            ps_data = ps_data[0]

        # Some PS versions store an integer in "Status", others store a string
        raw_status = ps_data.get("Status", None)
        status_msg = ps_data.get("StatusMessage", "")

        if isinstance(raw_status, int):
            # e.g., raw_status=0 => "Valid", raw_status=1 => "Invalid", etc.
            result["status"] = f"{raw_status} ({status_msg})"
        else:
            # Possibly "Valid", "NotSigned", or something else
            str_status = str(raw_status) if raw_status is not None else "Unknown"
            # Combine with the status message if it exists
            if status_msg:
                result["status"] = f"{str_status} ({status_msg})"
            else:
                result["status"] = str_status

        signer_cert = ps_data.get("SignerCertificate", {})
        result["issuer"] = signer_cert.get("IssuerName")
        result["subject"] = signer_cert.get("Subject")
        result["valid_from"] = signer_cert.get("NotBefore")
        result["valid_to"] = signer_cert.get("NotAfter")

    except Exception as e:
        result["status"] = f"Exception: {e}"

    return result

def get_process_info(
    minimal: bool = False,
    user_only: bool = False,
    all_processes: bool = False,
    verbose: bool = False,
    check_signatures: bool = False
) -> List[Dict]:
    """
    Scans running processes and returns a list of dictionaries containing process metadata and SHA256 hash.
    
    Options:
      - minimal: if True, only path + hash
      - user_only: if True, filters out system processes
      - all_processes: if True, includes both user and system processes
      - verbose: if True, gathers extra info (CPU usage, memory usage, parent name)
      - check_signatures: if True, attempts digital signature checks (Windows-only, PowerShell required)
    """
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'create_time', 'ppid']):
        try:
            # Make sure we have a valid exe path
            if not proc.info['exe'] or not os.path.isfile(proc.info['exe']):
                continue

            # user_only => skip system processes
            if user_only and proc.info['username'] and (
                proc.info['username'].lower().startswith('system') or
                proc.info['username'].lower().startswith('nt authority')
            ):
                continue

            # Default is "system only" if neither all_processes nor user_only
            if not all_processes and not user_only:
                if proc.info['username'] and not proc.info['username'].lower().startswith('system') \
                   and not proc.info['username'].lower().startswith('nt authority'):
                    continue

            # Compute the SHA256
            hashed = hash_file(proc.info['exe'])
            if not hashed:
                continue

            if minimal:
                # Minimal: just path + hash
                processes.append({
                    'path': proc.info['exe'],
                    'hash': hashed
                })
            else:
                # Build a richer dict
                proc_entry = {
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'path': proc.info['exe'],
                    'hash': hashed,
                    'username': proc.info['username'],
                    'ppid': proc.info['ppid'],
                    'created': proc.info['create_time']
                }

                if verbose:
                    # Extra info: CPU usage, memory usage, parent process name
                    ppid = proc.info['ppid']
                    parent_name = None
                    try:
                        if ppid and ppid > 0:
                            parent_proc = psutil.Process(ppid)
                            parent_name = parent_proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    try:
                        cpu_percent = proc.cpu_percent(interval=None)
                    except psutil.AccessDenied:
                        cpu_percent = None

                    try:
                        mem_percent = proc.memory_percent()
                    except psutil.AccessDenied:
                        mem_percent = None

                    proc_entry.update({
                        'parent_name': parent_name,
                        'cpu_percent': cpu_percent,
                        'memory_percent': mem_percent
                    })

                # If signature checks are enabled, do it
                if check_signatures:
                    sig_info = check_signature(proc.info['exe'])
                    proc_entry['signature'] = sig_info

                processes.append(proc_entry)

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
        except Exception:
            continue

    return processes
