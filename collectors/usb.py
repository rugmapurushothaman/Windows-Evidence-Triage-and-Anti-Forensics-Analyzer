"""
usb.py

Windows Evidence Triage & Anti-Forensics Analyzer

USB Device Collector

Author: Rugma Purushothaman
"""

import winreg


def collect_usb_devices():

    usb_devices = []

    registry_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"

    try:

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            registry_path
        )

        device_count = winreg.QueryInfoKey(key)[0]

        for i in range(device_count):

            device_name = winreg.EnumKey(key, i)

            device_key = winreg.OpenKey(
                key,
                device_name
            )

            serial_count = winreg.QueryInfoKey(device_key)[0]

            for j in range(serial_count):

                serial_number = winreg.EnumKey(
                    device_key,
                    j
                )

                usb_devices.append({

                    "device_name": device_name,
                    "serial_number": serial_number

                })

    except FileNotFoundError:

        print("USB Registry key not found.")

    except PermissionError:

        print("Permission denied while reading Registry.")

    except Exception as error:

        print("USB Collector Error:", error)

    return usb_devices
