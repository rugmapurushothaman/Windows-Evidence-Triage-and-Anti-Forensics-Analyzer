# analyzers/browser_cleanup.py

from utils.logger import get_logger


logger = get_logger("browser_cleanup")


def analyze_browser_artifacts(browser_data):
    """
    Analyze browser collector output.

    Expected example:

    {
        "browser": "Chrome",
        "history_count": 100,
        "download_count": 10,
        "cookie_count": 50,
        "history_path": "...",
        "history_exists": True
    }
    """

    findings = []

    if not isinstance(browser_data, dict):
        return findings

    browser = browser_data.get(
        "browser",
        "Unknown"
    )

    history_exists = browser_data.get(
        "history_exists",
        False
    )

    history_count = browser_data.get(
        "history_count",
        0
    )

    download_count = browser_data.get(
        "download_count",
        0
    )

    # Browser database unavailable
    if not history_exists:

        findings.append({
            "type": "BROWSER_HISTORY_UNAVAILABLE",
            "severity": "MEDIUM",
            "browser": browser,
            "description":
                "Browser history database was not available "
                "at the expected location."
        })

    # Empty history database
    elif history_count == 0:

        findings.append({
            "type": "EMPTY_BROWSER_HISTORY",
            "severity": "MEDIUM",
            "browser": browser,
            "description":
                "Browser history database exists but contains "
                "no detected history records."
        })

    # Downloads exist while history is empty
    if download_count > 0 and history_count == 0:

        findings.append({
            "type": "BROWSER_ACTIVITY_MISMATCH",
            "severity": "HIGH",
            "browser": browser,
            "description":
                "Downloads were detected while browser history "
                "contains no detected records."
        })

    return findings


def analyze_all_browsers(browser_results):

    findings = []

    if not browser_results:
        return findings

    for browser_data in browser_results:

        try:

            browser_findings = analyze_browser_artifacts(
                browser_data
            )

            findings.extend(browser_findings)

        except Exception as error:

            logger.error(
                "Browser analysis error: %s",
                error
            )

    return findings
