# utils/helpers.py

import os
import datetime


def safe_get(dictionary, key, default=None):
    """
    Safely retrieve a value from a dictionary.
    """
    if not isinstance(dictionary, dict):
        return default

    return dictionary.get(key, default)


def file_exists(path):
    """
    Check whether a file exists.
    """
    try:
        return os.path.isfile(path)
    except Exception:
        return False


def directory_exists(path):
    """
    Check whether a directory exists.
    """
    try:
        return os.path.isdir(path)
    except Exception:
        return False


def convert_timestamp(timestamp):
    """
    Convert a Windows timestamp / Unix timestamp
    into a readable datetime string.
    """

    try:
        if timestamp is None:
            return None

        if isinstance(timestamp, datetime.datetime):
            return timestamp.strftime("%Y-%m-%d %H:%M:%S")

        return datetime.datetime.fromtimestamp(
            float(timestamp)
        ).strftime("%Y-%m-%d %H:%M:%S")

    except Exception:
        return str(timestamp)


def is_hidden_file(path):
    """
    Check Windows hidden attribute.
    """

    try:
        import ctypes

        FILE_ATTRIBUTE_HIDDEN = 0x2

        attributes = ctypes.windll.kernel32.GetFileAttributesW(path)

        if attributes == -1:
            return False

        return bool(attributes & FILE_ATTRIBUTE_HIDDEN)

    except Exception:
        return False


def get_file_extension(path):
    """
    Return file extension in lowercase.
    """

    try:
        return os.path.splitext(path)[1].lower()
    except Exception:
        return ""


def normalize_path(path):
    """
    Normalize Windows path.
    """

    try:
        return os.path.normpath(path)
    except Exception:
        return path


def safe_int(value, default=0):
    """
    Safely convert a value to integer.
    """

    try:
        return int(value)
    except Exception:
        return default
