import pytest
import requests

from hvac import exceptions
from hvac.adapters import JSONAdapter
from hvac.api.system_backend.wrapping import Wrapping

UNWRAP_URL = "http://vault.example.com/v1/sys/wrapping/unwrap"
CLIENT_TOKEN = "client-token-in-use-by-other-requests"
WRAPPING_TOKEN = "wrapping-token-from-handoff"
EXPECTED_PATH = "auth/approle/role/database/secret-id"

LOOKUP_BODY = {
    "request_id": "lookup-request",
    "data": {
        "creation_path": EXPECTED_PATH,
        "creation_ttl": 300,
        "ttl": 120,
    },
}
UNWRAP_BODY = {
    "request_id": "unwrap-request",
    "data": {"secret_id": "the-handover-secret"},
}


class FakeResponse:
    """Minimal stand-in for requests.Response used by the fake transport."""

    def __init__(self, body=None, status_code=200):
        self._body = body if body is not None else {}
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self.headers = {"Content-Type": "application/json"}
        self.text = str(self._body)

    def json(self):
        return self._body


class FakeTransport:
    """Records the token, path and call count of every request.

    Queued outcomes are consumed in order; an outcome may be either a
    FakeResponse (returned) or an Exception (raised).
    """

    def __init__(self, outcomes=None):
        self.outcomes = list(outcomes or [])
        self.calls = []

    def request(self, method, url, headers=None, **kwargs):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "token": (headers or {}).get("X-Vault-Token"),
                "json": kwargs.get("json"),
            }
        )
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    @property
    def call_count(self):
        return len(self.calls)

    @property
    def tokens(self):
        return [call["token"] for call in self.calls]

    @property
    def paths(self):
        return [call["url"] for call in self.calls]


class FakeSession:
    verify = False
    cert = None
    proxies = {}

    def __init__(self, transport):
        self.transport = transport

    def request(self, *args, **kwargs):
        return self.transport.request(*args, **kwargs)

    def close(self):
        pass


@pytest.fixture
def transport():
    return FakeTransport()


@pytest.fixture
def wrapping(transport):
    adapter = JSONAdapter(
        base_uri="http://vault.example.com",
        token=CLIENT_TOKEN,
        session=FakeSession(transport),
    )
    return Wrapping(adapter), adapter


def test_unwrap_verified_looks_up_then_unwraps(wrapping, transport):
    api, adapter = wrapping
    transport.outcomes = [FakeResponse(LOOKUP_BODY), FakeResponse(UNWRAP_BODY)]

    result = api.unwrap_verified(WRAPPING_TOKEN, EXPECTED_PATH)

    assert result == UNWRAP_BODY
    assert transport.call_count == 2

    lookup_call, unwrap_call = transport.calls
    assert lookup_call["url"] == UNWRAP_URL
    assert lookup_call["token"] == WRAPPING_TOKEN
    assert lookup_call["json"] is None
    assert unwrap_call["url"] == UNWRAP_URL
    assert unwrap_call["json"] == {"token": WRAPPING_TOKEN}
    assert unwrap_call["token"] == CLIENT_TOKEN
    # The shared client token is never replaced, even transiently.
    assert adapter.token == CLIENT_TOKEN
    # The wrapping token only travels as a header on the lookup call.
    assert lookup_call["token"] == WRAPPING_TOKEN


def test_path_mismatch_does_not_consume_token(wrapping, transport):
    api, _adapter = wrapping
    transport.outcomes = [
        FakeResponse(
            {
                "data": {
                    "creation_path": "auth/token/create/suspicious",
                }
            }
        )
    ]

    with pytest.raises(exceptions.WrappingPathMismatch) as exc_info:
        api.unwrap_verified(WRAPPING_TOKEN, EXPECTED_PATH)

    assert exc_info.value.expected_path == EXPECTED_PATH
    assert exc_info.value.actual_path == "auth/token/create/suspicious"
    # Only the lookup happened: no consuming unwrap request was sent.
    assert transport.call_count == 1
    assert transport.calls[0]["token"] == WRAPPING_TOKEN
    assert transport.calls[0]["json"] is None


def test_expired_wrapping_token_is_reported_without_unwrap(wrapping, transport):
    api, _adapter = wrapping
    transport.outcomes = [
        FakeResponse(
            {"errors": ["wrapping token is expired"]},
            status_code=400,
        )
    ]

    with pytest.raises(exceptions.WrappingTokenExpired):
        api.unwrap_verified(WRAPPING_TOKEN, EXPECTED_PATH)

    assert transport.call_count == 1
    assert transport.calls[0]["token"] == WRAPPING_TOKEN


def test_already_unwrapped_token_is_classified(wrapping, transport):
    api, _adapter = wrapping
    transport.outcomes = [
        FakeResponse(
            {"errors": ["wrapping token is not valid or does not exist"]},
            status_code=400,
        )
    ]

    with pytest.raises(exceptions.WrappingTokenAlreadyUsed):
        api.unwrap_verified(WRAPPING_TOKEN, EXPECTED_PATH)

    assert transport.call_count == 1


def test_lookup_timeout_gives_recovery_guidance(wrapping, transport):
    api, _adapter = wrapping
    transport.outcomes = [requests.exceptions.ReadTimeout("read timed out")]

    with pytest.raises(exceptions.WrappingResultUnknown) as exc_info:
        api.unwrap_verified(WRAPPING_TOKEN, EXPECTED_PATH)

    assert transport.call_count == 1
    message = str(exc_info.value)
    assert EXPECTED_PATH in message
    assert "not consumed" in message
    assert "fresh wrapping token" in message


def test_unwrap_timeout_gives_recovery_guidance(wrapping, transport):
    api, _adapter = wrapping
    transport.outcomes = [
        FakeResponse(LOOKUP_BODY),
        requests.exceptions.ReadTimeout("read timed out"),
    ]

    with pytest.raises(exceptions.WrappingResultUnknown) as exc_info:
        api.unwrap_verified(WRAPPING_TOKEN, EXPECTED_PATH)

    assert transport.call_count == 2
    message = str(exc_info.value)
    assert EXPECTED_PATH in message
    assert "single-use" in message
    assert "auth/token/lookup" in message
    assert "re-wrap" in message


def test_client_token_remains_untouched_across_failure(wrapping, transport):
    api, adapter = wrapping
    transport.outcomes = [requests.exceptions.ConnectTimeout("unreachable")]

    with pytest.raises(exceptions.WrappingResultUnknown):
        api.unwrap_verified(WRAPPING_TOKEN, EXPECTED_PATH)

    assert adapter.token == CLIENT_TOKEN
    assert transport.tokens == [WRAPPING_TOKEN]


def test_missing_token_fails_before_any_request(wrapping, transport):
    api, _adapter = wrapping

    with pytest.raises(exceptions.ParamValidationError):
        api.unwrap_verified("", EXPECTED_PATH)

    assert transport.call_count == 0


def test_missing_expected_path_fails_before_any_request(wrapping, transport):
    api, _adapter = wrapping

    with pytest.raises(exceptions.ParamValidationError):
        api.unwrap_verified(WRAPPING_TOKEN, None)

    assert transport.call_count == 0
