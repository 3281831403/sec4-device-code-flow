"""Device authorization flow for television and console sign-in.

The module keeps all state in plain Python dictionaries so the flow can be
exercised without a database.  A store has four sections: devices, user_codes,
tokens and a monotonically increasing seq counter.  The public helpers cover
issuing codes, checking their shape, checking user-code attempts and polling
cadence, authorizing a device, exchanging an authorized code for a token,
validating policy, and processing a batch of independent issuance requests.
"""

from __future__ import annotations

import base64
import hashlib
import math
import secrets

DEVICE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

DEFAULT_POLICY = {
    "device_code_length": 16,
    "device_code_entropy_bits": 80,
    "device_code_max_length": 64,
    "user_code_length": 8,
    "max_attempts": 5,
    "poll_interval": 5,
    "expires_in": 600,
}

_VERIFICATION_URI = "https://example.invalid/device"


def _ensure_store(store: dict) -> None:
    """Create the sections used by the flow when they are missing."""
    if not isinstance(store, dict):
        raise TypeError("store must be a mapping")
    if not isinstance(store.get("devices"), dict):
        store["devices"] = {}
    if not isinstance(store.get("user_codes"), dict):
        store["user_codes"] = {}
    if not isinstance(store.get("tokens"), dict):
        store["tokens"] = {}
    if not isinstance(store.get("seq"), int) or store.get("seq") < 0:
        store["seq"] = 0


def _positive_int(policy: dict, key: str, default: int) -> int:
    value = policy.get(key) if isinstance(policy, dict) else None
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return default


def _ttl(policy: dict) -> int:
    for key in ("expires_in", "ttl", "device_code_ttl"):
        value = policy.get(key) if isinstance(policy, dict) else None
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return DEFAULT_POLICY["expires_in"]


def _max_attempts(policy: dict) -> int:
    return _positive_int(policy, "max_attempts", DEFAULT_POLICY["max_attempts"])


def _poll_interval(policy: dict) -> int:
    return _positive_int(policy, "poll_interval", DEFAULT_POLICY["poll_interval"])


def _device_code_length(policy: dict) -> int:
    """Return how many characters an issued device code should have."""
    return _positive_int(policy, "device_code_length", DEFAULT_POLICY["device_code_length"])


def _user_code_length(policy: dict) -> int:
    return _positive_int(policy, "user_code_length", DEFAULT_POLICY["user_code_length"])


def _entropy_material(entropy) -> bytes:
    if isinstance(entropy, (bytes, bytearray, memoryview)):
        return bytes(entropy)
    if isinstance(entropy, str):
        return entropy.encode("utf-8")
    if isinstance(entropy, int) and not isinstance(entropy, bool) and entropy >= 0:
        size = max(1, (entropy.bit_length() + 7) // 8)
        return entropy.to_bytes(size, "big")
    if entropy is None:
        return b""
    raise TypeError("entropy must be bytes, text or a non-negative integer")


def _b32(data: bytes, length: int) -> str:
    encoded = base64.b32encode(data).decode("ascii").rstrip("=")
    if not encoded:
        encoded = "A"
    repeats = max(1, math.ceil(length / len(encoded)))
    return (encoded * repeats)[:length]


def _normalize_user_code(code) -> str:
    if not isinstance(code, str):
        return ""
    return code.strip().upper()


def _failure(reason: str, **fields) -> dict:
    result = {
        "ok": False,
        "device_code": fields.get("device_code", ""),
        "user_code": fields.get("user_code", ""),
        "account": fields.get("account", ""),
        "status": fields.get("status", "invalid"),
        "expires_at": fields.get("expires_at"),
        "poll_interval": fields.get("poll_interval"),
        "reason": reason,
    }
    if "token" in fields:
        result["token"] = fields.get("token", "")
    return result


def _record_failed_attempt(record: dict) -> None:
    record["attempts"] = int(record.get("attempts", 0)) + 1
    limit = record.get("max_attempts")
    if isinstance(limit, int) and limit > 0 and record["attempts"] >= limit:
        record["status"] = "invalidated"


def issue(store: dict, entropy, now: int, policy: dict) -> dict:
    """Issue a device code and its matching user code.

    The returned mapping contains the code pair, the expiry instant and the
    polling interval that the client must honour.
    """
    _ensure_store(store)
    if not isinstance(now, int) or isinstance(now, bool):
        raise TypeError("now must be an integer")
    if not isinstance(policy, dict):
        policy = {}

    material = _entropy_material(entropy)
    if not material:
        material = b"device-flow-default-entropy"

    sequence = store["seq"]
    store["seq"] = sequence + 1

    device_seed = (
        b"device-code:"
        + material
        + b":"
        + str(now).encode("ascii")
        + b":"
        + str(sequence).encode("ascii")
    )
    device_digest = hashlib.sha256(device_seed).digest()
    device_code = _b32(device_digest, _device_code_length(policy))

    user_seed = (
        b"user-code:"
        + material
        + b":"
        + str(now).encode("ascii")
        + b":"
        + str(sequence).encode("ascii")
    )
    user_digest = hashlib.sha256(user_seed).digest()
    user_code = _b32(user_digest, _user_code_length(policy))

    expires_at = now + _ttl(policy)
    interval = _poll_interval(policy)
    attempts_limit = _max_attempts(policy)

    record = {
        "device_code": device_code,
        "user_code": user_code,
        "status": "pending",
        "account": "",
        "created_at": now,
        "expires_at": expires_at,
        "authorized_at": None,
        "attempts": 0,
        "max_attempts": attempts_limit,
        "poll_interval": interval,
        "last_poll_at": None,
        "used": False,
        "token": "",
    }
    store["devices"][device_code] = record
    store["user_codes"][user_code] = device_code

    return {
        "ok": True,
        "device_code": device_code,
        "user_code": user_code,
        "expires_at": expires_at,
        "poll_interval": interval,
        "status": "pending",
        "verification_uri": _VERIFICATION_URI,
    }


def check_code_format(code, policy: dict) -> bool:
    """Return True when a device code has the configured shape."""
    if not isinstance(code, str) or not code:
        return False
    minimum = _device_code_length(policy)
    maximum = _positive_int(policy, "device_code_max_length", DEFAULT_POLICY["device_code_max_length"])
    if maximum < minimum:
        maximum = minimum
    if not (minimum <= len(code) <= maximum):
        return False
    return all(character in DEVICE_ALPHABET for character in code)


def check_user_code(attempts, policy: dict) -> bool:
    """Return True when another user-code attempt is still permitted."""
    if not isinstance(attempts, int) or isinstance(attempts, bool):
        return False
    if attempts < 0:
        return False
    limit = _max_attempts(policy)
    return attempts < limit


def check_polling(interval, policy: dict) -> bool:
    """Return True when the delay between polls is acceptable."""
    if isinstance(interval, bool) or not isinstance(interval, (int, float)):
        return False
    return interval >= _poll_interval(policy)


def authorize(store: dict, user_code, account, now: int) -> dict:
    """Authorize a pending device using its user code.

    A successful call binds the account to the device record and moves it to
    the authorized state, from which one token exchange is possible.
    """
    _ensure_store(store)
    if not isinstance(now, int) or isinstance(now, bool):
        raise TypeError("now must be an integer")

    normalized = _normalize_user_code(user_code)
    device_code = store["user_codes"].get(normalized)
    if not device_code:
        return _failure("unknown user code")

    record = store["devices"].get(device_code)
    if not isinstance(record, dict):
        return _failure("unknown device code")

    if record.get("status") != "pending":
        return _failure(
            "device is not pending",
            device_code=device_code,
            status=record.get("status"),
            expires_at=record.get("expires_at"),
            poll_interval=record.get("poll_interval"),
        )

    expires_at = record.get("expires_at")
    if isinstance(expires_at, int) and now >= expires_at:
        record["status"] = "expired"
        return _failure(
            "user code has expired",
            device_code=device_code,
            status="expired",
            expires_at=expires_at,
            poll_interval=record.get("poll_interval"),
        )

    limit = record.get("max_attempts")
    if (
        isinstance(limit, int)
        and limit > 0
        and int(record.get("attempts", 0)) >= limit
    ):
        record["status"] = "invalidated"
        return _failure(
            "too many failed attempts",
            device_code=device_code,
            status="invalidated",
            expires_at=expires_at,
            poll_interval=record.get("poll_interval"),
        )

    if not isinstance(account, str) or not account.strip():
        _record_failed_attempt(record)
        return _failure(
            "account is required",
            device_code=device_code,
            status=record.get("status"),
            expires_at=record.get("expires_at"),
            poll_interval=record.get("poll_interval"),
        )

    record["status"] = "authorized"
    record["account"] = account.strip()
    record["authorized_at"] = now
    return {
        "ok": True,
        "device_code": device_code,
        "user_code": normalized,
        "account": record["account"],
        "status": "authorized",
        "expires_at": record.get("expires_at"),
        "poll_interval": record.get("poll_interval"),
        "reason": "",
    }


def exchange(store: dict, device_code, now: int) -> dict:
    """Exchange an authorized device code for a bearer token.

    The device code is meant to be a one-time credential.  Polling too soon
    is rejected before any token is produced.
    """
    _ensure_store(store)
    if not isinstance(now, int) or isinstance(now, bool):
        raise TypeError("now must be an integer")

    record = store["devices"].get(device_code) if isinstance(device_code, str) else None
    if not isinstance(record, dict):
        return _failure("unknown device code", device_code=device_code if isinstance(device_code, str) else "")

    interval = record.get("poll_interval")
    last_poll_at = record.get("last_poll_at")
    if (
        isinstance(last_poll_at, int)
        and isinstance(interval, int)
        and interval > 0
        and now - last_poll_at < interval
    ):
        return _failure(
            "polling too quickly",
            device_code=device_code,
            status=record.get("status"),
            expires_at=record.get("expires_at"),
            poll_interval=interval,
        )
    record["last_poll_at"] = now

    if record.get("used") or record.get("status") != "authorized":
        return _failure(
            "authorization is not complete",
            device_code=device_code,
            status=record.get("status"),
            expires_at=record.get("expires_at"),
            poll_interval=record.get("poll_interval"),
        )

    expires_at = record.get("expires_at")
    if isinstance(expires_at, int) and now >= expires_at:
        record["status"] = "expired"
        return _failure(
            "device code has expired",
            device_code=device_code,
            status="expired",
            expires_at=expires_at,
            poll_interval=record.get("poll_interval"),
        )

    token = secrets.token_urlsafe(32)
    record["token"] = token
    record["used"] = True
    record["status"] = "used"
    store["tokens"][token] = {
        "device_code": device_code,
        "account": record.get("account", ""),
        "issued_at": now,
    }
    return {
        "ok": True,
        "token": token,
        "token_type": "bearer",
        "device_code": device_code,
        "account": record.get("account", ""),
        "status": "used",
        "expires_at": record.get("expires_at"),
        "reason": "",
    }


def validate_policy(policy: dict) -> list[str]:
    """Return the problems that make a device-code policy unusable."""
    if not isinstance(policy, dict):
        return ["policy must be a mapping"]

    problems: list[str] = []

    interval = policy.get("poll_interval")
    if not isinstance(interval, int) or isinstance(interval, bool) or interval <= 0:
        problems.append("poll_interval is required")

    expiry = policy.get("expires_in")
    if not isinstance(expiry, int) or isinstance(expiry, bool) or expiry <= 0:
        problems.append("expires_in is required")

    length = policy.get("device_code_length")
    if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
        problems.append("device_code_length is required")

    entropy_bits = policy.get("device_code_entropy_bits")
    if not isinstance(entropy_bits, int) or isinstance(entropy_bits, bool) or entropy_bits <= 0:
        problems.append("device_code_entropy_bits is required")

    max_length = policy.get("device_code_max_length")
    if not isinstance(max_length, int) or isinstance(max_length, bool) or max_length <= 0:
        problems.append("device_code_max_length is required")

    user_code_length = policy.get("user_code_length")
    if not isinstance(user_code_length, int) or isinstance(user_code_length, bool) or user_code_length <= 0:
        problems.append("user_code_length is required")

    max_attempts = policy.get("max_attempts")
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts <= 0:
        problems.append("max_attempts is required")

    if (
        isinstance(length, int)
        and not isinstance(length, bool)
        and length > 0
        and isinstance(max_length, int)
        and not isinstance(max_length, bool)
        and max_length > 0
        and max_length < length
    ):
        problems.append("device_code_max_length must be at least device_code_length")

    return problems


def device_batch(requests: list[dict], store: dict, now: int) -> dict:
    """Issue device codes for several independent requests.

    Every request carries its own entropy and policy.  A malformed request
    becomes a failed result and does not prevent later requests from running.
    """
    _ensure_store(store)
    if not isinstance(requests, list):
        raise TypeError("requests must be a list")

    results: list[dict] = []

    for index, request in enumerate(requests):
        request_id = index
        if isinstance(request, dict):
            request_id = request.get("request_id", request.get("id", index))
        try:
            if not isinstance(request, dict):
                raise TypeError("request must be a mapping")
            policy = request.get("policy")
            if not isinstance(policy, dict):
                policy = {}
            issued = issue(store, request.get("entropy", b""), now, policy)
            results.append(
                {
                    "request_id": request_id,
                    "ok": True,
                    "device_code": issued["device_code"],
                    "user_code": issued["user_code"],
                    "expires_at": issued["expires_at"],
                    "poll_interval": issued["poll_interval"],
                    "status": issued["status"],
                    "reason": "",
                }
            )
        except Exception as exc:  # each request is reported independently
            results.append(
                {
                    "request_id": request_id,
                    "ok": False,
                    "device_code": "",
                    "user_code": "",
                    "expires_at": None,
                    "poll_interval": None,
                    "status": "invalid",
                    "reason": str(exc),
                }
            )

    ok_count = sum(1 for result in results if result["ok"])
    return {
        "results": results,
        "ok_count": ok_count,
        "all_ok": bool(results) and ok_count == len(results),
    }