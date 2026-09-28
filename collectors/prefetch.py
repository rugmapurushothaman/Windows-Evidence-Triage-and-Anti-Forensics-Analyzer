# collectors/prefetch.py

import os
import glob

from utils.logger import get_logger


logger = get_logger("prefetch_collector")


def get_prefetch_directory():

    windows_directory = os.environ.get(
        "WINDIR",
        "C:\\Windows"
    )

    return os.path.join(
        windows_directory,
        "Prefetch"
    )


def collect_prefetch():

    results = []

    prefetch_directory = get_prefetch_directory()

    if not os.path.isdir(prefetch_directory):

        logger.warning(
            "Prefetch directory not found: %s",
            prefetch_directory
        )

        return results

    try:

        pattern = os.path.join(
            prefetch_directory,
            "*.pf"
        )

        for file_path in glob.glob(pattern):

            try:

                stat_info = os.stat(
                    file_path
                )

                results.append({
                    "type": "PREFETCH",
                    "name": os.path.basename(
                        file_path
                    ),
                    "path": file_path,
                    "size_bytes": stat_info.st_size,
                    "created_time": stat_info.st_ctime,
                    "modified_time": stat_info.st_mtime,
                    "accessed_time": stat_info.st_atime
                })

            except Exception as error:

                logger.error(
                    "Prefetch file error: %s",
                    error
                )

    except Exception as error:

        logger.error(
            "Prefetch collection error: %s",
            error
        )

    return results
