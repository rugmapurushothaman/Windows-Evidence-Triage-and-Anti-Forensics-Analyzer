# correlation/timeline.py

import datetime

from utils.logger import get_logger


logger = get_logger("timeline")


def get_event_time(event):

    """
    Try to obtain the most useful timestamp
    from an event.
    """

    if not isinstance(event, dict):
        return None

    possible_fields = [
        "timestamp",
        "created_time",
        "modified_time",
        "accessed_time",
        "time"
    ]

    for field in possible_fields:

        value = event.get(field)

        if value is not None:
            return value

    return None


def normalize_time(value):

    if value is None:
        return None

    if isinstance(
        value,
        datetime.datetime
    ):
        return value

    try:

        return datetime.datetime.fromtimestamp(
            float(value)
        )

    except Exception:

        return None


def create_timeline(events):

    timeline = []

    if not events:
        return timeline

    for event in events:

        if not isinstance(event, dict):
            continue

        timestamp = get_event_time(
            event
        )

        normalized_time = normalize_time(
            timestamp
        )

        timeline.append({
            "timestamp": normalized_time,
            "type": event.get(
                "type",
                "UNKNOWN"
            ),
            "description": event.get(
                "description",
                event.get(
                    "name",
                    ""
                )
            ),
            "path": event.get(
                "path",
                ""
            ),
            "severity": event.get(
                "severity",
                "INFO"
            ),
            "source": event.get(
                "source",
                "unknown"
            )
        })

    # Events without timestamps go to the end
    timeline.sort(
        key=lambda item: (
            item["timestamp"] is None,
            item["timestamp"]
        )
    )

    return timeline


def print_timeline(timeline):

    print("")
    print("=" * 70)
    print("Forensic Timeline")
    print("=" * 70)

    if not timeline:

        print("No timeline events found.")
        return

    for event in timeline:

        timestamp = event.get(
            "timestamp"
        )

        if timestamp:

            timestamp_text = timestamp.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        else:

            timestamp_text = "UNKNOWN TIME"

        print(
            "[{}] [{}] {}".format(
                timestamp_text,
                event.get(
                    "type",
                    "UNKNOWN"
                ),
                event.get(
                    "description",
                    ""
                )
            )
        )
