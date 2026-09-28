# correlation/risk_engine.py

from utils.constants import RISK_LOW
from utils.constants import RISK_MEDIUM
from utils.constants import RISK_HIGH
from utils.constants import RISK_CRITICAL

from utils.logger import get_logger


logger = get_logger("risk_engine")


RISK_POINTS = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 5,
    "CRITICAL": 8
}


def get_finding_points(finding):

    if not isinstance(finding, dict):
        return 0

    severity = finding.get(
        "severity",
        "LOW"
    )

    return RISK_POINTS.get(
        severity.upper(),
        1
    )


def calculate_score(findings):

    score = 0

    for finding in findings:

        score += get_finding_points(
            finding
        )

    return score


def determine_risk(score):

    if score >= 20:
        return RISK_CRITICAL

    if score >= 10:
        return RISK_HIGH

    if score >= 5:
        return RISK_MEDIUM

    return RISK_LOW


def correlate_findings(findings):

    if not findings:

        return {
            "score": 0,
            "risk": RISK_LOW,
            "finding_count": 0,
            "findings": []
        }

    score = calculate_score(
        findings
    )

    risk = determine_risk(
        score
    )

    return {
        "score": score,
        "risk": risk,
        "finding_count": len(findings),
        "findings": findings
    }


def print_risk_summary(result):

    print("")
    print("=" * 70)
    print("Risk Assessment")
    print("=" * 70)

    print(
        "Risk Level       : {}".format(
            result.get(
                "risk",
                "UNKNOWN"
            )
        )
    )

    print(
        "Risk Score       : {}".format(
            result.get(
                "score",
                0
            )
        )
    )

    print(
        "Total Findings   : {}".format(
            result.get(
                "finding_count",
                0
            )
        )
    )

    print("")

    for finding in result.get(
        "findings",
        []
    ):

        print(
            "[{}] {} - {}".format(
                finding.get(
                    "severity",
                    "UNKNOWN"
                ),
                finding.get(
                    "type",
                    "UNKNOWN"
                ),
                finding.get(
                    "description",
                    ""
                )
            )
        )
