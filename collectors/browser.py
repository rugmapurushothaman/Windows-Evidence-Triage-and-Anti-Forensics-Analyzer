# collectors/browser.py

import os
import sqlite3
import shutil
import tempfile

from utils.logger import get_logger


logger = get_logger("browser_collector")


def get_user_profile():
    """
    Return the current Windows user profile.
    """

    return os.environ.get(
        "USERPROFILE",
        ""
    )


def copy_database(database_path):
    """
    Copy a browser SQLite database to a temporary location.

    Browser databases may be locked while the browser is running.
    """

    if not os.path.isfile(database_path):
        return None

    try:

        temp_directory = tempfile.mkdtemp(
            prefix="forensic_browser_"
        )

        destination = os.path.join(
            temp_directory,
            os.path.basename(database_path)
        )

        shutil.copy2(
            database_path,
            destination
        )

        return destination

    except Exception as error:

        logger.error(
            "Could not copy browser database: %s",
            error
        )

        return None


def count_chromium_history(database):

    count = 0

    try:

        connection = sqlite3.connect(
            database
        )

        cursor = connection.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM urls"
        )

        result = cursor.fetchone()

        if result:
            count = result[0]

        connection.close()

    except Exception as error:

        logger.error(
            "Chrome/Edge history error: %s",
            error
        )

    return count


def count_chromium_downloads(database):

    count = 0

    try:

        connection = sqlite3.connect(
            database
        )

        cursor = connection.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM downloads"
        )

        result = cursor.fetchone()

        if result:
            count = result[0]

        connection.close()

    except Exception:

        # Some Chromium versions/databases may not contain
        # the expected downloads table.
        pass

    return count


def collect_chromium_browser(
    browser_name,
    database_path
):

    result = {
        "browser": browser_name,
        "history_path": database_path,
        "history_exists": False,
        "history_count": 0,
        "download_count": 0
    }

    if not os.path.isfile(database_path):
        return result

    result["history_exists"] = True

    copied_database = copy_database(
        database_path
    )

    if not copied_database:
        return result

    result["history_count"] = count_chromium_history(
        copied_database
    )

    result["download_count"] = count_chromium_downloads(
        copied_database
    )

    return result


def collect_firefox_history(database_path):

    result = {
        "browser": "Firefox",
        "history_path": database_path,
        "history_exists": False,
        "history_count": 0,
        "download_count": 0
    }

    if not os.path.isfile(database_path):
        return result

    result["history_exists"] = True

    copied_database = copy_database(
        database_path
    )

    if not copied_database:
        return result

    try:

        connection = sqlite3.connect(
            copied_database
        )

        cursor = connection.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM moz_places"
        )

        result_data = cursor.fetchone()

        if result_data:
            result["history_count"] = result_data[0]

        connection.close()

    except Exception as error:

        logger.error(
            "Firefox history error: %s",
            error
        )

    return result


def collect_browser_artifacts():

    results = []

    profile = get_user_profile()

    if not profile:
        return results

    # Google Chrome
    chrome_path = os.path.join(
        profile,
        "AppData",
        "Local",
        "Google",
        "Chrome",
        "User Data",
        "Default",
        "History"
    )

    results.append(
        collect_chromium_browser(
            "Chrome",
            chrome_path
        )
    )

    # Microsoft Edge
    edge_path = os.path.join(
        profile,
        "AppData",
        "Local",
        "Microsoft",
        "Edge",
        "User Data",
        "Default",
        "History"
    )

    results.append(
        collect_chromium_browser(
            "Edge",
            edge_path
        )
    )

    # Firefox
    firefox_base = os.path.join(
        profile,
        "AppData",
        "Roaming",
        "Mozilla",
        "Firefox",
        "Profiles"
    )

    if os.path.isdir(firefox_base):

        try:

            for directory in os.listdir(
                firefox_base
            ):

                profile_path = os.path.join(
                    firefox_base,
                    directory
                )

                history_path = os.path.join(
                    profile_path,
                    "places.sqlite"
                )

                if os.path.isfile(history_path):

                    results.append(
                        collect_firefox_history(
                            history_path
                        )
                    )

        except Exception as error:

            logger.error(
                "Firefox profile error: %s",
                error
            )

    return results
