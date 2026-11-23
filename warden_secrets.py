"""
Warden secrets: keeping tool keys (tokens, API keys) safe.

Two jobs:

1. LOCK keys on disk.
   Tool servers get their keys through "env" (environment variables), e.g.
       "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "github_pat_..."}
   When Warden saves such settings (servers.json, protected.json, backups) every
   env value is encrypted with Windows' own lock, DPAPI. Only this Windows user
   on this PC can unlock it: a copied file is useless anywhere else. Chrome and
   Edge protect saved passwords the same way. Locked values look like
       "warden-dpapi:AQAAANCMnd8BFdERjHoAwE..."
   They are unlocked only in memory, just before Warden starts the tool server.

2. STOP keys from leaking.
   secret_values() lists the keys Warden holds. The gateway blocks any action whose
   details contain one of them (an attacker trying to send your key somewhere), and
   hides them in tool results and logs ("[hidden key]").

The AI never gets the keys: they go only to the tool server program as it starts.
Never log a key, not even when something goes wrong.
"""

from __future__ import annotations

import base64
import copy
import ctypes
import os
import re
from typing import Any

PREFIX = "warden-dpapi:"
HIDDEN = "[hidden key]"
# Extra "salt" mixed into the lock, so other programs using DPAPI cannot
# accidentally unlock Warden's values without knowing it.
_ENTROPY = b"Warden tool keys v1"

# An env value counts as a secret if its NAME says so...
SECRET_NAME = re.compile(r"key|token|secret|pass|pwd|pat\b|auth|credential|cookie|session", re.IGNORECASE)
MIN_SECRET_LENGTH = 8          # shorter values ("1", "true") would cause false alarms


class SecretError(Exception):
    """A key could not be locked or unlocked. The message never contains the key."""


# ---------------------------------------------------------------------------
# Windows DPAPI (CryptProtectData / CryptUnprotectData) through ctypes
# ---------------------------------------------------------------------------

def can_lock() -> bool:
    return os.name == "nt"


if os.name == "nt":
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _UI_FORBIDDEN = 0x1        # never show a Windows prompt

    def _blob(data: bytes) -> tuple[_Blob, Any]:
        buffer = ctypes.create_string_buffer(data, len(data))
        return _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer

    def _dpapi(data: bytes, lock: bool) -> bytes:
        data_in, keep1 = _blob(data)
        entropy, keep2 = _blob(_ENTROPY)
        out = _Blob()
        fn = _crypt32.CryptProtectData if lock else _crypt32.CryptUnprotectData
        ok = fn(ctypes.byref(data_in), None, ctypes.byref(entropy), None, None, _UI_FORBIDDEN, ctypes.byref(out))
        if not ok:
            raise SecretError(f"Windows could not {'lock' if lock else 'unlock'} the key "
                              f"(error {ctypes.get_last_error()})")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _kernel32.LocalFree(out.pbData)


def is_locked(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def lock(value: str) -> str:
    """Encrypt one value. Already locked values are left alone."""
    if is_locked(value):
        return value
    if not can_lock():
        raise SecretError("Locking keys is only available on Windows")
    return PREFIX + base64.b64encode(_dpapi(value.encode("utf-8"), lock=True)).decode("ascii")


def unlock(value: Any) -> Any:
    """Decrypt one value. Plain values (from older files) are returned as they are."""
    if not is_locked(value):
        return value
    if not can_lock():
        raise SecretError("This key was locked on Windows and can only be unlocked there")
    try:
        raw = base64.b64decode(value[len(PREFIX):], validate=True)
    except ValueError:
        raise SecretError("A locked key is damaged") from None
    return _dpapi(raw, lock=False).decode("utf-8")


# ---------------------------------------------------------------------------
# Server settings: lock / unlock every "env" value
# ---------------------------------------------------------------------------

def lock_spec(spec: Any) -> Any:
    """A copy of one server's settings with its env values locked (Windows only)."""
    if not isinstance(spec, dict) or not isinstance(spec.get("env"), dict) or not can_lock():
        return spec
    out = copy.deepcopy(spec)
    out["env"] = {k: lock(v) if isinstance(v, str) else v for k, v in spec["env"].items()}
    return out


def unlock_spec(spec: Any) -> Any:
    """A copy of one server's settings with its env values unlocked. Raises SecretError."""
    if not isinstance(spec, dict) or not isinstance(spec.get("env"), dict):
        return spec
    out = copy.deepcopy(spec)
    out["env"] = {k: unlock(v) for k, v in spec["env"].items()}
    return out


def lock_servers(servers: Any) -> Any:
    """Lock every server in a {"name": spec} block."""
    if not isinstance(servers, dict):
        return servers
    return {name: lock_spec(spec) for name, spec in servers.items()}


def has_plain_keys(servers: Any) -> bool:
    """True if any env value in this block is still unlocked (an older file)."""
    if not isinstance(servers, dict):
        return False
    return any(isinstance(v, str) and v and not is_locked(v)
               for spec in servers.values() if isinstance(spec, dict) and isinstance(spec.get("env"), dict)
               for v in spec["env"].values())


# ---------------------------------------------------------------------------
# Leak protection
# ---------------------------------------------------------------------------

def looks_like_secret(name: str, value: Any) -> bool:
    """Is this env value a key worth guarding? (paths and short flags are not)"""
    if not isinstance(value, str) or len(value) < MIN_SECRET_LENGTH or is_locked(value):
        return False
    if SECRET_NAME.search(name):
        return True
    # Unnamed, but shaped like a key: long, no spaces, letters AND digits, not a path or web address.
    return (len(value) >= 20 and not re.search(r"\s|[/\\]", value)
            and bool(re.search(r"[A-Za-z]", value)) and bool(re.search(r"\d", value)))


def secret_values(servers: dict[str, Any]) -> list[str]:
    """Every key held in the (already unlocked) server settings, longest first."""
    found: set[str] = set()
    for spec in servers.values():
        if isinstance(spec, dict) and isinstance(spec.get("env"), dict):
            found.update(v for k, v in spec["env"].items() if looks_like_secret(k, v))
    return sorted(found, key=len, reverse=True)


def contains_secret(value: Any, secrets: list[str]) -> bool:
    """Does any string inside this JSON-like value contain one of the keys?"""
    if not secrets:
        return False
    if isinstance(value, str):
        return any(s in value for s in secrets)
    if isinstance(value, list):
        return any(contains_secret(v, secrets) for v in value)
    if isinstance(value, dict):
        return any(contains_secret(k, secrets) or contains_secret(v, secrets) for k, v in value.items())
    return False


def redact(value: Any, secrets: list[str]) -> Any:
    """A copy of a JSON-like value with every key replaced by "[hidden key]"."""
    if not secrets:
        return value
    if isinstance(value, str):
        for s in secrets:              # longest first, so a key inside a longer key is handled
            value = value.replace(s, HIDDEN)
        return value
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    if isinstance(value, dict):
        return {redact(k, secrets): redact(v, secrets) for k, v in value.items()}
    return value
