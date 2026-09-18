"""
ads.py

Windows Evidence Triage & Anti-Forensics Analyzer

Alternate Data Stream (ADS) Analyzer

Author: Rugma Purushothaman

Purpose:
--------
Detect NTFS Alternate Data Streams associated with files.

Important:
-----------
An ADS is not automatically malicious.
Some streams, such as Zone.Identifier, can be legitimate
Windows metadata.
"""

import ctypes
from ctypes import wintypes


# ---------------------------------------------------------
# Windows API structures
# ---------------------------------------------------------

class WIN32_FIND_STREAM_DATA(ctypes.Structure):

    _fields_ = [
        ("StreamSize", ctypes.c_longlong),
        ("StreamName", wintypes.WCHAR * 296)
    ]


# ---------------------------------------------------------
# Windows API functions
# ---------------------------------------------------------

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

FindFirstStreamW = kernel32.FindFirstStreamW
FindFirstStreamW.argtypes = [
    wintypes.LPCWSTR,
    ctypes.c_int,
    ctypes.POINTER(WIN32_FIND_STREAM_DATA),
    wintypes.DWORD
]
FindFirstStreamW.restype = wintypes.HANDLE


FindNextStreamW = kernel32.FindNextStreamW
FindNextStreamW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(WIN32_FIND_STREAM_DATA)
]
FindNextStreamW.restype = wintypes.BOOL


FindClose = kernel32.FindClose
FindClose.argtypes = [wintypes.HANDLE]
FindClose.restype = wintypes.BOOL


INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


# ---------------------------------------------------------
# ADS detection for one file
# ---------------------------------------------------------

def find_ads(file_path):

    streams = []

    data = WIN32_FIND_STREAM_DATA()

    handle = FindFirstStreamW(
        file_path,
        0,
        ctypes.byref(data),
        0
    )

    if handle == INVALID_HANDLE_VALUE:

        return streams

    try:

        while True:

            stream_name = data.StreamName
            stream_size = data.StreamSize

            # The normal/default data stream is:
            # ::$DATA
            #
            # We only want Alternate Data Streams.

            if stream_name != "::$DATA":

                streams.append({
                    "stream_name": stream_name,
                    "size_bytes": stream_size
                })

            if not FindNextStreamW(
                handle,
                ctypes.byref(data)
            ):

                break

    finally:

        FindClose(handle)

    return streams


# ---------------------------------------------------------
# Analyze collected files
# ---------------------------------------------------------

def analyze_ads(files):

    findings = []

    for file_info in files:

        file_path = file_info.get("path")

        if not file_path:
            continue

        try:

            streams = find_ads(file_path)

        except Exception:

            continue

        if len(streams) == 0:
            continue

        findings.append({
            "name": file_info.get("name"),
            "path": file_path,
            "streams": streams
        })

    return findings
