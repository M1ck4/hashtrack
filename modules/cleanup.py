import os
import shutil
from datetime import datetime, timedelta

def cleanup_logs(base_folder: str, keep_days: int, ask_confirmation: bool = True) -> None:
    """
    Deletes log folders older than `keep_days`.
    Prompts user before deleting unless ask_confirmation is False.
    """
    now = datetime.now()
    cutoff = now - timedelta(days=keep_days)

    if not os.path.exists(base_folder):
        return

    folders_to_delete = []

    for folder_name in os.listdir(base_folder):
        folder_path = os.path.join(base_folder, folder_name)
        if not os.path.isdir(folder_path):
            continue
        try:
            folder_date = datetime.strptime(folder_name, "%Y-%m-%d")
            if folder_date < cutoff:
                folders_to_delete.append(folder_path)
        except ValueError:
            continue  # skip non-date folders

    if not folders_to_delete:
        return

    print("\n🧹 Log Cleanup")
    print(f"Found {len(folders_to_delete)} folders older than {keep_days} days:")
    for folder in folders_to_delete:
        print(f" - {folder}")

    if ask_confirmation:
        confirm = input("\nDelete these folders? [Y/N]: ").strip().lower()
        if confirm != 'y':
            print("Cleanup cancelled.")
            return

    for folder in folders_to_delete:
        try:
            shutil.rmtree(folder)
            print(f"✅ Deleted {folder}")
        except Exception as e:
            print(f"[!] Failed to delete {folder}: {e}")