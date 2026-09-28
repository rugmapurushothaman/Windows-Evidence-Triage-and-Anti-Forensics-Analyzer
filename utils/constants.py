# utils/constants.py

# Risk levels
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".dll",
    ".sys",
    ".com"
]

# Windows event IDs commonly useful for anti-forensics triage
EVENT_LOG_CLEARED = 1102
SECURITY_LOGON = 4624
SECURITY_LOGOFF = 4634
FAILED_LOGON = 4625
PROCESS_CREATED = 4688
CREDENTIAL_ACCESS = 5379

# Suspicious directories
SUSPICIOUS_DIRECTORIES = [
    "\\Temp\\",
    "\\AppData\\Local\\Temp\\",
    "\\Users\\Public\\",
    "\\Windows\\Temp\\",
    "\\ProgramData\\"
]

# Browser names
BROWSERS = [
    "Chrome",
    "Edge",
    "Firefox"
]

# Timeline event types
EVENT_TYPE_FILE = "FILE"
EVENT_TYPE_BROWSER = "BROWSER"
EVENT_TYPE_PREFETCH = "PREFETCH"
EVENT_TYPE_RECYCLE_BIN = "RECYCLE_BIN"
EVENT_TYPE_LOG = "EVENT_LOG"
EVENT_TYPE_USB = "USB"

# Timestamp anomaly types
TIMESTAMP_MODIFIED_BEFORE_CREATED = "MODIFIED_BEFORE_CREATED"
TIMESTAMP_ACCESS_BEFORE_CREATED = "ACCESS_BEFORE_CREATED"

# ADS
ADS_STREAM_INDICATOR = ":$DATA"
