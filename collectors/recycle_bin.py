# collectors/recycle_bin.py

import os
import glob

from utils.logger import get_logger


logger = get_logger("recycle_bin")


def get_recycle_bin_paths():

    paths = []

    for drive_letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":

        recycle_path = (
            drive_letter +
            ":\\$Recycle.Bin"
        )

        if os.path.isdir(recycle_path):

            paths.append(
                recycle_path
            )

    return paths


def collect_recycle_bin():

    results = []

    recycle_paths = get_recycle_bin_paths()

    for recycle_path in recycle_paths:

        try:

            for root, directories, files in os.walk(
                recycle_path
            ):

                for filename in files:

                    file_path = os.path.join(
                        root,
                        filename
                    )

                    try:

                        stat_info = os.stat(
                            file_path
                        )

                        results.append({
                            "type": "RECYCLE_BIN",
                            "name": filename,
                            "path": file_path,
                            "size_bytes": stat_info.st_size,
                            "created_time": stat_info.st_ctime,
                            "modified_time": stat_info.st_mtime,
                            "accessed_time": stat_info.st_atime
                        })

                    except Exception:
                        pass

        except Exception as error:

            logger.error(
                "Recycle Bin error: %s",
                error
            )

    return results
