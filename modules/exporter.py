import os
import json
import csv
from datetime import datetime
from typing import List, Dict

DEFAULT_LOG_DIR = "logs"

def get_output_folder_path(base_folder: str = DEFAULT_LOG_DIR) -> str:
    today = datetime.now().strftime("%Y-%m-%d")
    return os.path.join(base_folder, today)

def ensure_output_folder(base_folder: str = DEFAULT_LOG_DIR) -> str:
    output_path = get_output_folder_path(base_folder)
    os.makedirs(output_path, exist_ok=True)
    return output_path

def generate_filename(prefix: str = "hashtrack", ext: str = ".json") -> str:
    timestamp = datetime.now().strftime("%H-%M-%S")
    return f"{prefix}_{timestamp}{ext}"

def write_json(data: List[Dict], folder: str, filename: str) -> str:
    path = os.path.join(folder, filename)
    try:
        os.makedirs(folder, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        return path
    except Exception as e:
        print(f"[!] Failed to write JSON file: {e}")
        return ""

def write_csv(data: List[Dict], folder: str, filename: str) -> str:
    path = os.path.join(folder, filename)
    try:
        if not data:
            return ""
        os.makedirs(folder, exist_ok=True)
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            for row in data:
                writer.writerow(row)
        return path
    except Exception as e:
        print(f"[!] Failed to write CSV file: {e}")
        return ""