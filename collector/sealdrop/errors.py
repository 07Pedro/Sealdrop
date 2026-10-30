"""Why a sealed file or a delivery is turned away (PROTOCOL.md §5, §6)."""

# Whole-file reasons, in receipts' "rejected" list.
DAMAGED = "damaged"
TOO_BIG = "too-big"
UNKNOWN_SENDER = "unknown-sender"
BAD_SIGNATURE = "bad-signature"
BAD_CONTENT = "bad-content"

# Per-delivery reasons, in a delivery's "reason".
BAD_NAME = "bad-name"
BAD_FILE = "bad-file"
NO_FILES = "no-files"


class Rejected(Exception):
    """A sealed file fails a check. `reason` is one of the whole-file reasons above."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class FormatError(ValueError):
    """Text that breaks §3's rules (JSON, base64url, hex)."""
