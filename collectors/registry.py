"""
registry.py

Registry Collector

Author: Rugma Purushothaman

Collects basic information from the Windows Registry.
"""

import winreg


def collect_installed_programs():

    uninstall_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

    programs = []

    try:

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            uninstall_path
        )

        subkeys = winreg.QueryInfoKey(key)[0]

        for i in range(subkeys):

            try:

                subkey_name = winreg.EnumKey(key, i)

                subkey = winreg.OpenKey(key, subkey_name)

                try:

                    display_name = winreg.QueryValueEx(
                        subkey,
                        "DisplayName"
                    )[0]

                    programs.append(display_name)

                except FileNotFoundError:
                    pass

            except:
                pass

    except:
        pass

    return programs
