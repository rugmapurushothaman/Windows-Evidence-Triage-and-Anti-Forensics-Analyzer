# collectors/browser.py
#
# Windows Browser Forensic Collector
#
# Collects:
#   1. Browser history
#   2. Search activity extracted from history
#   3. Browser downloads
#   4. SQLite WAL/SHM evidence
#   5. Cleanup / deletion indicators
#
# Supported:
#   Chrome
#   Microsoft Edge
#   Firefox
#
# Python 3.6 compatible.

import os
import sqlite3
import shutil
import tempfile
import datetime
import urllib.parse


# ============================================================
# GENERAL HELPERS
# ============================================================

def _chrome_time(value):
    """
    Convert Chrome/Edge WebKit timestamp to datetime string.

    Chrome timestamps:
    microseconds since 1601-01-01 UTC.
    """

    try:
        value = int(value)

        if value == 0:
            return ""

        epoch = datetime.datetime(
            1601,
            1,
            1
        )

        dt = epoch + datetime.timedelta(
            microseconds=value
        )

        return dt.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except Exception:
        return ""


def _firefox_time(value):
    """
    Convert Firefox PRTime.

    Firefox uses microseconds since Unix epoch.
    """

    try:
        value = int(value)

        if value == 0:
            return ""

        epoch = datetime.datetime(
            1970,
            1,
            1
        )

        dt = epoch + datetime.timedelta(
            microseconds=value
        )

        return dt.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except Exception:
        return ""


def _copy_sqlite_database(db_path):
    """
    Copy a SQLite database and its WAL/SHM files to a temporary
    directory before analysis.

    This prevents the forensic tool from modifying the original
    browser database.
    """

    if not db_path:
        return None

    if not os.path.isfile(db_path):
        return None

    temp_dir = tempfile.mkdtemp(
        prefix="browser_forensic_"
    )

    try:

        database_copy = os.path.join(
            temp_dir,
            os.path.basename(db_path)
        )

        shutil.copy2(
            db_path,
            database_copy
        )

        # SQLite WAL
        wal_path = db_path + "-wal"

        if os.path.isfile(wal_path):

            shutil.copy2(
                wal_path,
                database_copy + "-wal"
            )

        # SQLite SHM
        shm_path = db_path + "-shm"

        if os.path.isfile(shm_path):

            shutil.copy2(
                shm_path,
                database_copy + "-shm"
            )

        return {
            "directory": temp_dir,
            "database": database_copy,
            "wal": database_copy + "-wal",
            "shm": database_copy + "-shm"
        }

    except Exception:

        try:
            shutil.rmtree(
                temp_dir,
                ignore_errors=True
            )
        except Exception:
            pass

        return None


def _open_readonly_database(database_path):
    """
    Open copied SQLite database in read-only mode.
    """

    try:

        connection = sqlite3.connect(
            "file:{}?mode=ro".format(
                database_path
            ),
            uri=True
        )

        return connection

    except Exception:
        return None


def _extract_search_activity(url):
    """
    Extract search activity from browser history URLs.

    This does not claim to be a separate browser search database.
    It identifies search-engine URLs in the browsing history.
    """

    if not url:
        return None

    try:

        parsed = urllib.parse.urlparse(
            url
        )

        hostname = (
            parsed.netloc or ""
        ).lower()

        query_params = urllib.parse.parse_qs(
            parsed.query
        )

        # Google
        if "google." in hostname:

            if "q" in query_params:

                return {
                    "search_engine": "Google",
                    "query": query_params[
                        "q"
                    ][0]
                }

        # Bing
        if "bing.com" in hostname:

            if "q" in query_params:

                return {
                    "search_engine": "Bing",
                    "query": query_params[
                        "q"
                    ][0]
                }

        # DuckDuckGo
        if "duckduckgo.com" in hostname:

            if "q" in query_params:

                return {
                    "search_engine": "DuckDuckGo",
                    "query": query_params[
                        "q"
                    ][0]
                }

        # Yahoo
        if "search.yahoo." in hostname:

            if "p" in query_params:

                return {
                    "search_engine": "Yahoo",
                    "query": query_params[
                        "p"
                    ][0]
                }

    except Exception:
        pass

    return None


# ============================================================
# CHROME / EDGE
# ============================================================

def _collect_chromium_history(
    browser_name,
    database_path
):
    """
    Collect Chromium browser history.

    Works with Chrome and Edge History databases.
    """

    result = {
        "browser": browser_name,
        "history_exists": False,
        "history": [],
        "search_activity": [],
        "downloads": [],
        "deleted_history": [],
        "deleted_downloads": [],
        "cleanup_indicators": [],
        "database": database_path,
        "wal_present": False,
        "shm_present": False
    }

    if not database_path:
        return result

    if not os.path.isfile(database_path):
        return result

    result[
        "history_exists"
    ] = True

    copied = _copy_sqlite_database(
        database_path
    )

    if not copied:
        return result

    result[
        "wal_present"
    ] = os.path.isfile(
        copied["wal"]
    )

    result[
        "shm_present"
    ] = os.path.isfile(
        copied["shm"]
    )

    connection = _open_readonly_database(
        copied["database"]
    )

    if not connection:
        return result

    try:

        cursor = connection.cursor()

        # ----------------------------------------------------
        # HISTORY
        # ----------------------------------------------------

        try:

            cursor.execute(
                """
                SELECT
                    urls.url,
                    urls.title,
                    urls.visit_count,
                    visits.visit_time
                FROM urls
                LEFT JOIN visits
                    ON urls.id = visits.url
                ORDER BY visits.visit_time DESC
                """
            )

            rows = cursor.fetchall()

            for row in rows:

                url = row[0] or ""
                title = row[1] or ""
                visit_count = row[2] or 0
                visit_time = _chrome_time(
                    row[3]
                )

                result[
                    "history"
                ].append({
                    "browser": browser_name,
                    "date_time": visit_time,
                    "url": url,
                    "title": title,
                    "visit_count": visit_count,
                    "source": "History SQLite"
                })

                search = _extract_search_activity(
                    url
                )

                if search:

                    result[
                        "search_activity"
                    ].append({
                        "browser": browser_name,
                        "date_time": visit_time,
                        "search_engine": search[
                            "search_engine"
                        ],
                        "query": search[
                            "query"
                        ],
                        "url": url,
                        "source": "History SQLite"
                    })

        except Exception as error:

            result[
                "cleanup_indicators"
            ].append({
                "type": "HISTORY_READ_ERROR",
                "description": str(error)
            })

        # ----------------------------------------------------
        # DOWNLOADS
        # ----------------------------------------------------

        try:

            cursor.execute(
                """
                SELECT
                    current_path,
                    target_path,
                    tab_url,
                    start_time,
                    end_time
                FROM downloads
                ORDER BY start_time DESC
                """
            )

            rows = cursor.fetchall()

            for row in rows:

                current_path = row[0] or ""
                target_path = row[1] or ""
                url = row[2] or ""

                start_time = _chrome_time(
                    row[3]
                )

                end_time = _chrome_time(
                    row[4]
                )

                file_path = (
                    current_path
                    or target_path
                )

                file_name = os.path.basename(
                    file_path
                )

                result[
                    "downloads"
                ].append({
                    "browser": browser_name,
                    "file": file_name,
                    "url": url,
                    "download_time": (
                        start_time
                        or end_time
                    ),
                    "path": file_path,
                    "source": "History SQLite"
                })

        except Exception as error:

            result[
                "cleanup_indicators"
            ].append({
                "type": "DOWNLOAD_READ_ERROR",
                "description": str(error)
            })

        # ----------------------------------------------------
        # DATABASE STATISTICS
        # ----------------------------------------------------

        try:

            cursor.execute(
                "SELECT COUNT(*) FROM urls"
            )

            history_count = cursor.fetchone()[0]

            if history_count == 0:

                result[
                    "cleanup_indicators"
                ].append({
                    "type": "EMPTY_HISTORY",
                    "description":
                        "Browser history database contains no URL records."
                })

        except Exception:
            pass

        try:

            cursor.execute(
                "SELECT COUNT(*) FROM downloads"
            )

            download_count = cursor.fetchone()[0]

            if (
                history_count > 0
                and download_count == 0
            ):

                result[
                    "cleanup_indicators"
                ].append({
                    "type": "NO_DOWNLOAD_RECORDS",
                    "description":
                        "No download records were found in the active database."
                })

        except Exception:
            pass

        # ----------------------------------------------------
        # WAL / SHM INDICATORS
        # ----------------------------------------------------

        if result[
            "wal_present"
        ]:

            result[
                "deleted_history"
            ].append({
                "browser": browser_name,
                "status":
                    "WAL artifact present",
                "source":
                    os.path.basename(
                        copied["wal"]
                    ),
                "description":
                    "SQLite WAL data may contain recent database transactions or records not yet merged into the main database."
            })

        if result[
            "shm_present"
        ]:

            result[
                "deleted_history"
            ].append({
                "browser": browser_name,
                "status":
                    "SHM artifact present",
                "source":
                    os.path.basename(
                        copied["shm"]
                    ),
                "description":
                    "SQLite shared-memory artifact is present and may assist forensic database recovery."
            })

        # ----------------------------------------------------
        # IMPORTANT:
        # WAL/SHM PRESENCE DOES NOT ITSELF PROVE DELETED DATA.
        # ----------------------------------------------------

        if (
            result["wal_present"]
            or result["shm_present"]
        ):

            result[
                "cleanup_indicators"
            ].append({
                "type": "SQLITE_RECOVERY_ARTIFACTS",
                "description":
                    "SQLite WAL/SHM artifacts are available for forensic examination. Their presence alone does not prove that browser history was deleted."
            })

    finally:

        try:
            connection.close()
        except Exception:
            pass

        try:
            shutil.rmtree(
                copied["directory"],
                ignore_errors=True
            )
        except Exception:
            pass

    return result


# ============================================================
# FIREFOX
# ============================================================

def _collect_firefox_history(
    browser_name,
    database_path
):
    """
    Collect Firefox places.sqlite history.
    """

    result = {
        "browser": browser_name,
        "history_exists": False,
        "history": [],
        "search_activity": [],
        "downloads": [],
        "deleted_history": [],
        "deleted_downloads": [],
        "cleanup_indicators": [],
        "database": database_path,
        "wal_present": False,
        "shm_present": False
    }

    if not database_path:
        return result

    if not os.path.isfile(database_path):
        return result

    result[
        "history_exists"
    ] = True

    copied = _copy_sqlite_database(
        database_path
    )

    if not copied:
        return result

    result[
        "wal_present"
    ] = os.path.isfile(
        copied["wal"]
    )

    result[
        "shm_present"
    ] = os.path.isfile(
        copied["shm"]
    )

    connection = _open_readonly_database(
        copied["database"]
    )

    if not connection:
        return result

    try:

        cursor = connection.cursor()

        # ----------------------------------------------------
        # FIREFOX HISTORY
        # ----------------------------------------------------

        try:

            cursor.execute(
                """
                SELECT
                    moz_places.url,
                    moz_places.title,
                    moz_places.visit_count,
                    moz_historyvisits.visit_date
                FROM moz_places
                LEFT JOIN moz_historyvisits
                    ON moz_places.id =
                       moz_historyvisits.place_id
                ORDER BY moz_historyvisits.visit_date DESC
                """
            )

            rows = cursor.fetchall()

            for row in rows:

                url = row[0] or ""
                title = row[1] or ""
                visit_count = row[2] or 0

                visit_time = _firefox_time(
                    row[3]
                )

                result[
                    "history"
                ].append({
                    "browser": browser_name,
                    "date_time": visit_time,
                    "url": url,
                    "title": title,
                    "visit_count": visit_count,
                    "source": "places.sqlite"
                })

                search = _extract_search_activity(
                    url
                )

                if search:

                    result[
                        "search_activity"
                    ].append({
                        "browser": browser_name,
                        "date_time": visit_time,
                        "search_engine": search[
                            "search_engine"
                        ],
                        "query": search[
                            "query"
                        ],
                        "url": url,
                        "source": "places.sqlite"
                    })

        except Exception as error:

            result[
                "cleanup_indicators"
            ].append({
                "type": "HISTORY_READ_ERROR",
                "description": str(error)
            })

        # ----------------------------------------------------
        # FIREFOX DOWNLOADS
        # ----------------------------------------------------

        try:

            cursor.execute(
                """
                SELECT
                    moz_places.url,
                    moz_annos.content,
                    moz_annos.dateAdded
                FROM moz_annos
                LEFT JOIN moz_places
                    ON moz_annos.place_id =
                       moz_places.id
                WHERE moz_annos.anno_attribute_id
                    IN (
                        SELECT id
                        FROM moz_anno_attributes
                        WHERE name LIKE '%download%'
                    )
                """
            )

            rows = cursor.fetchall()

            for row in rows:

                url = row[0] or ""
                path = row[1] or ""

                download_time = _firefox_time(
                    row[2]
                )

                result[
                    "downloads"
                ].append({
                    "browser": browser_name,
                    "file": os.path.basename(
                        path
                    ),
                    "url": url,
                    "download_time": download_time,
                    "path": path,
                    "source": "places.sqlite"
                })

        except Exception:
            # Firefox versions differ considerably.
            # Download history may instead be available
            # through other profile artifacts.
            pass

        # ----------------------------------------------------
        # EMPTY HISTORY
        # ----------------------------------------------------

        try:

            cursor.execute(
                """
                SELECT COUNT(*)
                FROM moz_places
                """
            )

            count = cursor.fetchone()[0]

            if count == 0:

                result[
                    "cleanup_indicators"
                ].append({
                    "type": "EMPTY_HISTORY",
                    "description":
                        "Firefox places database contains no URL records."
                })

        except Exception:
            pass

        # ----------------------------------------------------
        # WAL / SHM
        # ----------------------------------------------------

        if result[
            "wal_present"
        ]:

            result[
                "deleted_history"
            ].append({
                "browser": browser_name,
                "status":
                    "WAL artifact present",
                "source":
                    os.path.basename(
                        copied["wal"]
                    ),
                "description":
                    "SQLite WAL artifact may contain recent Firefox database transactions."
            })

        if result[
            "shm_present"
        ]:

            result[
                "deleted_history"
            ].append({
                "browser": browser_name,
                "status":
                    "SHM artifact present",
                "source":
                    os.path.basename(
                        copied["shm"]
                    ),
                "description":
                    "SQLite shared-memory artifact is present."
            })

    finally:

        try:
            connection.close()
        except Exception:
            pass

        try:
            shutil.rmtree(
                copied["directory"],
                ignore_errors=True
            )
        except Exception:
            pass

    return result


# ============================================================
# PROFILE DISCOVERY
# ============================================================

def _get_chrome_paths():
    """
    Return Chrome history database paths for the current Windows user.
    """

    user_profile = os.environ.get(
        "USERPROFILE",
        ""
    )

    base = os.path.join(
        user_profile,
        "AppData",
        "Local",
        "Google",
        "Chrome",
        "User Data"
    )

    paths = []

    if not os.path.isdir(base):
        return paths

    try:

        for name in os.listdir(base):

            profile_path = os.path.join(
                base,
                name
            )

            if not os.path.isdir(
                profile_path
            ):
                continue

            history_path = os.path.join(
                profile_path,
                "History"
            )

            if os.path.isfile(
                history_path
            ):
                paths.append(
                    history_path
                )

    except Exception:
        pass

    return paths


def _get_edge_paths():
    """
    Return Edge history database paths.
    """

    user_profile = os.environ.get(
        "USERPROFILE",
        ""
    )

    base = os.path.join(
        user_profile,
        "AppData",
        "Local",
        "Microsoft",
        "Edge",
        "User Data"
    )

    paths = []

    if not os.path.isdir(base):
        return paths

    try:

        for name in os.listdir(base):

            profile_path = os.path.join(
                base,
                name
            )

            if not os.path.isdir(
                profile_path
            ):
                continue

            history_path = os.path.join(
                profile_path,
                "History"
            )

            if os.path.isfile(
                history_path
            ):
                paths.append(
                    history_path
                )

    except Exception:
        pass

    return paths


def _get_firefox_paths():
    """
    Return Firefox places.sqlite databases.
    """

    user_profile = os.environ.get(
        "USERPROFILE",
        ""
    )

    base = os.path.join(
        user_profile,
        "AppData",
        "Roaming",
        "Mozilla",
        "Firefox",
        "Profiles"
    )

    paths = []

    if not os.path.isdir(base):
        return paths

    try:

        for profile in os.listdir(base):

            profile_path = os.path.join(
                base,
                profile
            )

            if not os.path.isdir(
                profile_path
            ):
                continue

            database_path = os.path.join(
                profile_path,
                "places.sqlite"
            )

            if os.path.isfile(
                database_path
            ):
                paths.append(
                    database_path
                )

    except Exception:
        pass

    return paths


# ============================================================
# MAIN COLLECTOR
# ============================================================

def collect_browser_artifacts(
    evidence_path=None
):
    """
    Collect browser forensic artifacts.

    Current implementation:
        - If evidence_path is supplied, attempt to locate browser
          profile artifacts inside it.
        - Otherwise examine the current Windows user profile.

    Returns:
        Dictionary keyed by browser.
    """

    results = {}

    # --------------------------------------------------------
    # CURRENT USER PROFILES
    # --------------------------------------------------------

    chrome_paths = _get_chrome_paths()
    edge_paths = _get_edge_paths()
    firefox_paths = _get_firefox_paths()

    # --------------------------------------------------------
    # CHROME
    # --------------------------------------------------------

    chrome_results = []

    for path in chrome_paths:

        chrome_results.append(
            _collect_chromium_history(
                "Chrome",
                path
            )
        )

    results[
        "Chrome"
    ] = chrome_results

    # --------------------------------------------------------
    # EDGE
    # --------------------------------------------------------

    edge_results = []

    for path in edge_paths:

        edge_results.append(
            _collect_chromium_history(
                "Microsoft Edge",
                path
            )
        )

    results[
        "Microsoft Edge"
    ] = edge_results

    # --------------------------------------------------------
    # FIREFOX
    # --------------------------------------------------------

    firefox_results = []

    for path in firefox_paths:

        firefox_results.append(
            _collect_firefox_history(
                "Firefox",
                path
            )
        )

    results[
        "Firefox"
    ] = firefox_results

    return results


# ============================================================
# SUMMARY HELPERS
# ============================================================

def flatten_browser_history(
    browser_results
):
    """
    Return all history records in one list.
    """

    records = []

    for browser_name in browser_results:

        profiles = browser_results[
            browser_name
        ]

        for profile in profiles:

            records.extend(
                profile.get(
                    "history",
                    []
                )
            )

    return records


def flatten_search_activity(
    browser_results
):
    """
    Return all search activity.
    """

    records = []

    for browser_name in browser_results:

        profiles = browser_results[
            browser_name
        ]

        for profile in profiles:

            records.extend(
                profile.get(
                    "search_activity",
                    []
                )
            )

    return records


def flatten_downloads(
    browser_results
):
    """
    Return all browser downloads.
    """

    records = []

    for browser_name in browser_results:

        profiles = browser_results[
            browser_name
        ]

        for profile in profiles:

            records.extend(
                profile.get(
                    "downloads",
                    []
                )
            )

    return records


def flatten_deleted_history(
    browser_results
):
    """
    Return recoverable/deletion-related history indicators.
    """

    records = []

    for browser_name in browser_results:

        profiles = browser_results[
            browser_name
        ]

        for profile in profiles:

            records.extend(
                profile.get(
                    "deleted_history",
                    []
                )
            )

    return records


def flatten_deleted_downloads(
    browser_results
):
    """
    Return recoverable/deletion-related download indicators.

    This is intentionally separate from normal downloads.
    """

    records = []

    for browser_name in browser_results:

        profiles = browser_results[
            browser_name
        ]

        for profile in profiles:

            records.extend(
                profile.get(
                    "deleted_downloads",
                    []
                )
            )

    return records


def flatten_cleanup_indicators(
    browser_results
):
    """
    Return browser cleanup indicators.
    """

    records = []

    for browser_name in browser_results:

        profiles = browser_results[
            browser_name
        ]

        for profile in profiles:

            records.extend(
                profile.get(
                    "cleanup_indicators",
                    []
                )
            )

    return records


# ============================================================
# TERMINAL TEST DISPLAY
# ============================================================

def print_browser_summary(
    browser_results
):
    """
    Print a useful browser forensic summary.
    """

    history = flatten_browser_history(
        browser_results
    )

    searches = flatten_search_activity(
        browser_results
    )

    downloads = flatten_downloads(
        browser_results
    )

    deleted_history = flatten_deleted_history(
        browser_results
    )

    deleted_downloads = flatten_deleted_downloads(
        browser_results
    )

    cleanup = flatten_cleanup_indicators(
        browser_results
    )

    print()
    print("=" * 80)
    print("BROWSER FORENSIC ANALYSIS")
    print("=" * 80)

    print(
        "History Records       : {}".format(
            len(history)
        )
    )

    print(
        "Search Activity       : {}".format(
            len(searches)
        )
    )

    print(
        "Download Records      : {}".format(
            len(downloads)
        )
    )

    print(
        "Deleted/Recovery Indicators: {}".format(
            len(deleted_history)
        )
    )

    print(
        "Deleted Download Indicators: {}".format(
            len(deleted_downloads)
        )
    )

    print(
        "Cleanup Indicators    : {}".format(
            len(cleanup)
        )
    )

    print()
    print("Recent History:")
    print("-" * 80)

    for record in history[:20]:

        print(
            "{} | {} | {}".format(
                record.get(
                    "date_time",
                    ""
                ),
                record.get(
                    "browser",
                    ""
                ),
                record.get(
                    "url",
                    ""
                )
            )
        )

    print()
    print("Search Activity:")
    print("-" * 80)

    for record in searches[:20]:

        print(
            "{} | {} | {}".format(
                record.get(
                    "date_time",
                    ""
                ),
                record.get(
                    "search_engine",
                    ""
                ),
                record.get(
                    "query",
                    ""
                )
            )
        )

    print()
    print("Downloads:")
    print("-" * 80)

    for record in downloads[:20]:

        print(
            "{} | {} | {}".format(
                record.get(
                    "download_time",
                    ""
                ),
                record.get(
                    "browser",
                    ""
                ),
                record.get(
                    "file",
                    ""
                )
            )
        )

    print()
    print("Recovery / Deletion Indicators:")
    print("-" * 80)

    for record in deleted_history[:20]:

        print(
            "{} | {} | {}".format(
                record.get(
                    "browser",
                    ""
                ),
                record.get(
                    "status",
                    ""
                ),
                record.get(
                    "source",
                    ""
                )
            )
        )

    print()
    print("=" * 80)
