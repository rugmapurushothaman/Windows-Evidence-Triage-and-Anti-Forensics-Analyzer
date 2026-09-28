# collectors/usb.py
# Windows USB Device Forensic Collector
#
# Collects USB device information from Windows Registry.
# It also attempts to correlate available timestamps from
# SetupAPI installation logs and Windows Event Logs.
#
# Python 3.6 compatible.

import os
import re
import glob
import datetime
import winreg


def _filetime_to_datetime(filetime):
    """
    Convert Windows FILETIME to Python datetime.
    """
    try:
        if not filetime:
            return None

        # FILETIME = number of 100-nanosecond intervals
        # since 1601-01-01 UTC
        value = int(filetime)

        epoch = datetime.datetime(1601, 1, 1)
        return epoch + datetime.timedelta(microseconds=value / 10)

    except Exception:
        return None


def _safe_reg_value(key, value_name):
    """
    Safely read a registry value.
    """
    try:
        return winreg.QueryValueEx(key, value_name)[0]
    except Exception:
        return ""


def _get_usb_storage_devices():
    """
    Read USBSTOR registry information.

    USBSTOR normally contains information about USB storage devices
    that Windows has recognized/installed.
    """

    devices = []

    registry_path = (
        r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    )

    try:
        root_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            registry_path
        )
    except Exception:
        return devices

    try:

        device_type_count = winreg.QueryInfoKey(root_key)[0]

        for i in range(device_type_count):

            try:
                device_type = winreg.EnumKey(root_key, i)

                type_key = winreg.OpenKey(
                    root_key,
                    device_type
                )

                device_instance_count = winreg.QueryInfoKey(type_key)[0]

                for j in range(device_instance_count):

                    try:
                        device_instance = winreg.EnumKey(
                            type_key,
                            j
                        )

                        instance_key = winreg.OpenKey(
                            type_key,
                            device_instance
                        )

                        device_info = {
                            "device_name": device_type,
                            "instance": device_instance,
                            "serial_number": device_instance,
                            "friendly_name": "",
                            "manufacturer": "",
                            "first_observed": "",
                            "last_observed": "",
                            "connection_count": 1,
                            "evidence_source": "USBSTOR Registry",
                            "observations": []
                        }

                        # Friendly name
                        friendly_name = _safe_reg_value(
                            instance_key,
                            "FriendlyName"
                        )

                        if friendly_name:
                            device_info["friendly_name"] = str(
                                friendly_name
                            )

                        # Manufacturer
                        manufacturer = _safe_reg_value(
                            instance_key,
                            "Mfg"
                        )

                        if manufacturer:
                            device_info["manufacturer"] = str(
                                manufacturer
                            )

                        # DeviceDesc may contain useful information
                        if not device_info["friendly_name"]:

                            device_desc = _safe_reg_value(
                                instance_key,
                                "DeviceDesc"
                            )

                            if device_desc:
                                device_info["friendly_name"] = str(
                                    device_desc
                                )

                        # Registry key last-write time
                        try:
                            key_info = winreg.QueryInfoKey(
                                instance_key
                            )

                            last_write_time = key_info[2]

                            dt = _filetime_to_datetime(
                                last_write_time
                            )

                            if dt:

                                formatted = dt.strftime(
                                    "%Y-%m-%d %H:%M:%S"
                                )

                                device_info[
                                    "last_observed"
                                ] = formatted

                                device_info[
                                    "first_observed"
                                ] = formatted

                                device_info[
                                    "observations"
                                ].append({
                                    "timestamp": formatted,
                                    "event": "Device observed",
                                    "source": "USBSTOR Registry"
                                })

                        except Exception:
                            pass

                        # Add the device
                        devices.append(device_info)

                        try:
                            winreg.CloseKey(instance_key)
                        except Exception:
                            pass

                    except Exception:
                        continue

                try:
                    winreg.CloseKey(type_key)
                except Exception:
                    pass

            except Exception:
                continue

    finally:
        try:
            winreg.CloseKey(root_key)
        except Exception:
            pass

    return devices


def _parse_setupapi_logs():
    """
    Search Windows SetupAPI logs for USB-related installation evidence.

    This does NOT assume every SetupAPI entry represents a physical
    connection. The results are treated as observations/installation
    evidence.
    """

    observations = []

    possible_files = [
        os.path.join(
            os.environ.get("WINDIR", r"C:\Windows"),
            "inf",
            "setupapi.dev.log"
        ),
        os.path.join(
            os.environ.get("WINDIR", r"C:\Windows"),
            "inf",
            "setupapi.app.log"
        )
    ]

    for log_file in possible_files:

        if not os.path.isfile(log_file):
            continue

        try:

            with open(
                log_file,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:

                current_timestamp = None
                current_device = None

                for line in f:

                    line = line.strip()

                    # SetupAPI timestamps commonly appear as:
                    #
                    # >>>  [Device Install]
                    # >>>  Section start 2026/03/19 14:21:33.123

                    timestamp_match = re.search(
                        r"Section start\s+"
                        r"(\d{4}/\d{2}/\d{2})\s+"
                        r"(\d{2}:\d{2}:\d{2})",
                        line,
                        re.IGNORECASE
                    )

                    if timestamp_match:

                        current_timestamp = (
                            timestamp_match.group(1)
                            .replace("/", "-")
                            + " "
                            + timestamp_match.group(2)
                        )

                    # Look for USBSTOR/USB information
                    upper_line = line.upper()

                    if (
                        "USBSTOR" in upper_line
                        or "\\USB\\" in upper_line
                        or "USB\\VID_" in upper_line
                    ):

                        current_device = line

                        if current_timestamp:

                            observations.append({
                                "timestamp": current_timestamp,
                                "event": "USB installation/observation",
                                "source": os.path.basename(
                                    log_file
                                ),
                                "detail": current_device
                            })

        except Exception:
            continue

    return observations


def _match_setupapi_to_devices(
    devices,
    setupapi_observations
):
    """
    Attempt to associate SetupAPI observations with USB devices.

    Matching is deliberately conservative.
    """

    for observation in setupapi_observations:

        detail = observation.get(
            "detail",
            ""
        ).upper()

        for device in devices:

            serial = str(
                device.get(
                    "serial_number",
                    ""
                )
            ).upper()

            instance = str(
                device.get(
                    "instance",
                    ""
                )
            ).upper()

            device_name = str(
                device.get(
                    "device_name",
                    ""
                )
            ).upper()

            matched = False

            if serial and serial in detail:
                matched = True

            elif instance and instance in detail:
                matched = True

            elif device_name and device_name in detail:
                matched = True

            if matched:

                device[
                    "observations"
                ].append({
                    "timestamp": observation.get(
                        "timestamp",
                        ""
                    ),
                    "event": observation.get(
                        "event",
                        ""
                    ),
                    "source": observation.get(
                        "source",
                        ""
                    ),
                    "detail": observation.get(
                        "detail",
                        ""
                    )
                })

    return devices


def _finalize_usb_devices(devices):
    """
    Calculate first observed, last observed and observation count.
    """

    for device in devices:

        observations = device.get(
            "observations",
            []
        )

        timestamps = []

        for observation in observations:

            timestamp = observation.get(
                "timestamp",
                ""
            )

            if timestamp:
                try:
                    dt = datetime.datetime.strptime(
                        timestamp,
                        "%Y-%m-%d %H:%M:%S"
                    )

                    timestamps.append(
                        dt
                    )

                except Exception:
                    pass

        if timestamps:

            timestamps.sort()

            device[
                "first_observed"
            ] = timestamps[0].strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            device[
                "last_observed"
            ] = timestamps[-1].strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        # Count unique observation timestamps/events.
        unique_events = set()

        for observation in observations:

            event_key = (
                observation.get(
                    "timestamp",
                    ""
                ),
                observation.get(
                    "event",
                    ""
                ),
                observation.get(
                    "source",
                    ""
                )
            )

            unique_events.add(
                event_key
            )

        device[
            "connection_count"
        ] = max(
            1,
            len(unique_events)
        )

        # Sort observations chronologically
        observations.sort(
            key=lambda x: x.get(
                "timestamp",
                ""
            )
        )

    return devices


def collect_usb_devices():
    """
    Main USB collector.

    Returns:
        list of dictionaries
    """

    devices = _get_usb_storage_devices()

    setupapi_observations = _parse_setupapi_logs()

    devices = _match_setupapi_to_devices(
        devices,
        setupapi_observations
    )

    devices = _finalize_usb_devices(
        devices
    )

    return devices


def get_usb_observations(device):
    """
    Return the detailed observation history for one USB device.
    """

    if not device:
        return []

    return device.get(
        "observations",
        []
    )


def print_usb_devices(devices):
    """
    Terminal display for testing.
    """

    print()
    print("=" * 80)
    print("USB DEVICE FORENSIC ANALYSIS")
    print("=" * 80)

    if not devices:
        print("No USB storage devices found.")
        return

    for index, device in enumerate(
        devices,
        1
    ):

        print()
        print("-" * 80)

        print(
            "Device          : {}".format(
                device.get(
                    "friendly_name",
                    ""
                )
            )
        )

        print(
            "USB Type        : {}".format(
                device.get(
                    "device_name",
                    ""
                )
            )
        )

        print(
            "Serial Number   : {}".format(
                device.get(
                    "serial_number",
                    ""
                )
            )
        )

        print(
            "Manufacturer    : {}".format(
                device.get(
                    "manufacturer",
                    ""
                )
            )
        )

        print(
            "First Observed  : {}".format(
                device.get(
                    "first_observed",
                    ""
                )
            )
        )

        print(
            "Last Observed   : {}".format(
                device.get(
                    "last_observed",
                    ""
                )
            )
        )

        print(
            "Observation Count: {}".format(
                device.get(
                    "connection_count",
                    0
                )
            )
        )

        print(
            "Evidence Source : {}".format(
                device.get(
                    "evidence_source",
                    ""
                )
            )
        )

        print()
        print("Observation History:")

        observations = device.get(
            "observations",
            []
        )

        if not observations:
            print("  No detailed observations available.")

        else:

            for observation in observations:

                print(
                    "  {} | {} | {}".format(
                        observation.get(
                            "timestamp",
                            ""
                        ),
                        observation.get(
                            "event",
                            ""
                        ),
                        observation.get(
                            "source",
                            ""
                        )
                    )
                )

    print()
    print("=" * 80)
