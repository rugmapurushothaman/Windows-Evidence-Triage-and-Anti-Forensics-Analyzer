"""
filesystem.py

File System Collector
"""

import os


def collect_files(path):

    file_list = []
    folder_count = 0

    for root, dirs, files in os.walk(path):

        folder_count += len(dirs)

        for file in files:
            file_list.append(os.path.join(root, file))

    return {
        "files": file_list,
        "file_count": len(file_list),
        "folder_count": folder_count
    }
