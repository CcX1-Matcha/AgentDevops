"""Conservative labels for advice text; no command is ever executed here."""
from __future__ import annotations

import re


_READ_ONLY = re.compile(
    r"^(?:df\b|du\b|free\b|dmesg\b|journalctl\b|ps\b|head\b|sort\b|"
    r"(?:e?grep)\b|ss\b|id\b|namei\b|vmstat\b|uptime\b|lsof\b|lsblk\b|"
    r"findmnt\b|date\b|getenforce\b|lastb\b|getent\b|ip\s+route\s*$|"
    r"systemctl\s+(?:status|--failed)\b|sshd\s+-T\b|nginx\s+-t\b|"
    r"openssl\s+x509\b|kubectl\s+(?:get|describe|logs|top)\b|"
    r"docker\s+(?:inspect|ps|logs|stats|version)\b|docker\s+(?:image|network)\s+(?:inspect|ls)\b|"
    r"docker\s+system\s+df\b|docker\s+info\b)"
)


def command_risk(command: str | None) -> str:
    if not command:
        return "manual"
    text = command.replace("2>/dev/null", "")
    if any(symbol in text for symbol in (";", "\n", "`", "$(", "${", "||")) or "&" in text.replace("&&", ""):
        return "manual"
    if re.search(r"[<>]", re.sub(r"<[^<>]+>", "PLACEHOLDER", text)) or re.search(r"(?:^|\s)(?:-out|--output)(?:\s|=)", text):
        return "manual"
    parts = re.split(r"\s*(?:&&|\|)\s*", text)
    return "read_only" if parts and all(_READ_ONLY.match(part.strip()) for part in parts) else "manual"
