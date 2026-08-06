"""
filesystem.py

Windows Evidence Triage & Anti-Forensics Analyzer

File System Collector

Author: Rugma Purushothaman
"""

import os
from datetime import datetime


def collect_files(path):

    file_list = []
    folder_count = 0

    for root, dirs, files in os.walk(path):

        folder_count += len(dirs)

        for file in files:

            full_path = os.path.join(root, file)

            try:

                stats = os.stat(full_path)

                file_info = {
                    "name": file,
                    "path": full_path,
                    "extension": os.path.splitext(file)[1],
                    "size_bytes": stats.st_size,
                    "created_time": datetime.fromtimestamp(
                        stats.st_ctime
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                    "modified_time": datetime.fromtimestamp(
                        stats.st_mtime
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                    "accessed_time": datetime.fromtimestamp(
                        stats.st_atime
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                    "is_hidden": file.startswith("."),
                    "directory": root
                }

                file_list.append(file_info)

            except (
                PermissionError,
                FileNotFoundError,
                OSError
            ):
                continue

    return {
        "files": file_list,
        "file_count": len(file_list),
        "folder_count": folder_count
    }
