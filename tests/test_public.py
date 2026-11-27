"""Public tests for the device-code sign-in flow."""

from devcode import (
    authorize,
    check_code_format,
    device_batch,
    exchange,
    issue,
)

NOW = 1000


def _policy() -> dict:
    return {
        "device_code_length": 16,
        "device_code_entropy_bits": 80,
        "device_code_max_length": 64,
        "user_code_length": 8,
        "max_attempts": 5,
        "poll_interval": 5,
        "expires_in": 600,
    }


def _store() -> dict:
    return {}


def test_issue_device_codes_have_enough_length_and_are_unique():
    store = _store()
    policy = _policy()

    first = issue(store, b"entropy-alpha", NOW, policy)
    second = issue(store, b"entropy-beta", NOW, policy)

    assert first["ok"] is True
    assert len(first["device_code"]) >= policy["device_code_length"]
    assert check_code_format(first["device_code"], policy) is True
    assert first["device_code"] != second["device_code"]
    assert first["user_code"] != second["user_code"]


def test_check_code_format_rejects_short_and_non_alphabet_codes():
    policy = _policy()

    assert check_code_format("A" * policy["device_code_length"], policy) is True
    assert check_code_format("A" * 8, policy) is False
    assert check_code_format("A" * 15 + "_", policy) is False


def test_authorize_accepts_normalized_user_code():
    store = _store()
    policy = _policy()
    issued = issue(store, b"entropy-alpha", NOW, policy)

    result = authorize(store, issued["user_code"].lower(), "alice", NOW + 10)

    assert result["ok"] is True
    assert result["device_code"] == issued["device_code"]
    assert result["account"] == "alice"
    assert result["status"] == "authorized"


def test_exchange_token_can_only_be_used_once():
    store = _store()
    policy = _policy()
    issued = issue(store, b"entropy-alpha", NOW, policy)
    assert authorize(store, issued["user_code"], "alice", NOW + 1)["ok"] is True

    first = exchange(store, issued["device_code"], NOW + 10)
    second = exchange(store, issued["device_code"], NOW + 20)

    assert first["ok"] is True
    assert first["token"]
    assert second["ok"] is False


def test_batch_requests_get_independent_codes():
    store = _store()
    policy = _policy()
    requests = [
        {"request_id": "first", "entropy": b"entropy-alpha", "policy": policy},
        {"request_id": "second", "entropy": b"entropy-beta", "policy": policy},
    ]

    batch = device_batch(requests, store, NOW)

    assert batch["all_ok"] is True
    assert [item["request_id"] for item in batch["results"]] == ["first", "second"]
    assert batch["results"][0]["device_code"] != batch["results"][1]["device_code"]
    assert batch["results"][0]["user_code"] != batch["results"][1]["user_code"]