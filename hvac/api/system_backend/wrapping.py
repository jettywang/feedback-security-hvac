import requests

from hvac import exceptions
from hvac.api.system_backend.system_backend_mixin import SystemBackendMixin

_WRAPPING_UNWRAP_PATH = "/v1/sys/wrapping/unwrap"
_LOOKUP_RESULT_UNKNOWN_MESSAGE = (
    "The wrapping token lookup for {path} did not complete, so the token was "
    "not consumed and its creation path could not be verified. Re-run the "
    "verification with the same token, or ask the issuer for a fresh wrapping "
    "token."
)
_LOOKUP_REJECTED_MESSAGE = (
    "Vault rejected the wrapping token lookup for {path}: {detail}. The token "
    "was not consumed. It may be expired or already unwrapped; ask the issuer "
    "for a fresh wrapping token."
)
_UNWRAP_RESULT_UNKNOWN_MESSAGE = (
    "The unwrap request for {path} timed out after it was sent, so the result "
    "is unknown: the single-use wrapping token may already have been consumed. "
    "Do not retry blindly. Check the outcome with a non-wrapping capability "
    "(for example auth/token/lookup or the wrapped secret's own identifier), "
    "and ask the issuer to re-wrap the secret if the outcome cannot be "
    "confirmed."
)
_EXPIRED_TOKEN_HINTS = ("wrapping token is expired",)
_ALREADY_USED_TOKEN_HINTS = (
    "wrapping token is not valid or does not exist",
    "wrapping token has already been used",
)


def _response_body(response):
    """Return the JSON body of a response regardless of the adapter in use."""
    if isinstance(response, dict):
        return response
    return response.json()


class Wrapping(SystemBackendMixin):
    def unwrap(self, token=None):
        """Return the original response inside the given wrapping token.

        Unlike simply reading cubbyhole/response (which is deprecated), this endpoint provides additional validation
        checks on the token, returns the original value on the wire rather than a JSON string representation of it, and
        ensures that the response is properly audit-logged.

        Supported methods:
            POST: /sys/wrapping/unwrap. Produces: 200 application/json

        :param token: Specifies the wrapping token ID. This is required if the client token is not the wrapping token.
            Do not use the wrapping token in both locations.
        :type token: str | unicode
        :return: The JSON response of the request.
        :rtype: dict
        """
        params = {}
        if token is not None:
            params["token"] = token

        api_path = "/v1/sys/wrapping/unwrap"
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def wrap(self, payload=None, ttl=60):
        """Wraps a serializable dictionary inside a wrapping token.

        Supported methods:
            POST: /sys/wrapping/wrap. Produces: 200 application/json

        :param payload: Specifies the data that should be wrapped inside the token.
        :type payload: dict
        :param ttl: The TTL of the returned wrapping token.
        :type ttl: int
        :return: The JSON response of the request.
        :rtype: dict
        """

        if payload is None:
            payload = {}

        api_path = "/v1/sys/wrapping/wrap"
        return self._adapter.post(
            url=api_path, json=payload, headers={"X-Vault-Wrap-TTL": "{}".format(ttl)}
        )

    def unwrap_verified(self, token, expected_creation_path):
        """Unwrap a wrapping token after verifying its creation path.

        The wrapping token is first sent as a non-consuming lookup (a POST to
        ``/sys/wrapping/unwrap`` with no request body and the token in the
        ``X-Vault-Token`` header). Its ``creation_path`` is compared against
        ``expected_creation_path`` before any unwrap is attempted, so a token
        created on an unexpected path is rejected without being consumed.

        The token travels in a per-request header instead of replacing the
        adapter's client token, so concurrent requests keep using their own
        token and the adapter's ``token`` attribute is left untouched.

        :param token: The wrapping token ID handed over for verification.
        :type token: str | unicode
        :param expected_creation_path: The path the wrapping token is expected
            to have been created from (its ``creation_path``).
        :type expected_creation_path: str | unicode
        :return: The JSON response of the unwrap request.
        :rtype: dict
        :raises hvac.exceptions.WrappingTokenExpired: If the wrapping token has
            expired. It was not consumed.
        :raises hvac.exceptions.WrappingTokenAlreadyUsed: If the wrapping token
            has already been unwrapped.
        :raises hvac.exceptions.WrappingPathMismatch: If the token's
            ``creation_path`` differs from ``expected_creation_path``. The token
            is not consumed by this failure.
        :raises hvac.exceptions.WrappingError: If Vault rejects the lookup for a
            reason that cannot be classified more specifically.
        :raises hvac.exceptions.WrappingResultUnknown: If a request times out
            and the state of the single-use token cannot be determined. The
            exception message describes how to recover.
        """
        if not token:
            raise exceptions.ParamValidationError(
                "A wrapping token is required for verified unwrap."
            )
        if not expected_creation_path:
            raise exceptions.ParamValidationError(
                "expected_creation_path is required to verify the wrapping "
                "token's provenance."
            )

        lookup_response = self._lookup_wrapping_token(
            token, expected_creation_path
        )
        lookup_body = _response_body(lookup_response)
        actual_creation_path = (lookup_body.get("data") or {}).get("creation_path")

        if actual_creation_path != expected_creation_path:
            message = (
                "Wrapping token creation path mismatch: expected "
                "'{expected}', got '{actual}'".format(
                    expected=expected_creation_path,
                    actual=actual_creation_path,
                )
            )
            raise exceptions.WrappingPathMismatch(
                message=message,
                expected_path=expected_creation_path,
                actual_path=actual_creation_path,
            )

        try:
            return self.unwrap(token)
        except requests.exceptions.Timeout as ex:
            raise exceptions.WrappingResultUnknown(
                message=_UNWRAP_RESULT_UNKNOWN_MESSAGE.format(
                    path=expected_creation_path
                )
            ) from ex

    def _lookup_wrapping_token(self, token, expected_creation_path):
        """Return the wrapping token's properties without consuming it.

        Vault treats an empty-body POST to sys/wrapping/unwrap carrying the
        wrapping token in the X-Vault-Token header as a lookup rather than an
        unwrap, so the single-use token remains valid afterwards.
        """
        try:
            return self._adapter.post(
                url=_WRAPPING_UNWRAP_PATH,
                token=token,
            )
        except requests.exceptions.Timeout as ex:
            raise exceptions.WrappingResultUnknown(
                message=_LOOKUP_RESULT_UNKNOWN_MESSAGE.format(
                    path=expected_creation_path
                )
            ) from ex
        except exceptions.InvalidRequest as ex:
            raise self._classify_invalid_wrapping_token(
                ex, expected_creation_path
            ) from ex

    @staticmethod
    def _classify_invalid_wrapping_token(exc, expected_creation_path):
        """Map Vault's lookup failures to the specific wrapping error."""
        error_text = " ".join(exc.errors or [])
        if exc.args and exc.args[0]:
            error_text = "{} {}".format(error_text, exc.args[0])
        error_text = error_text.lower()

        if any(hint in error_text for hint in _EXPIRED_TOKEN_HINTS):
            return exceptions.WrappingTokenExpired(
                message="The wrapping token has expired. Request a freshly "
                "wrapped secret from the issuer; this token was not consumed.",
                errors=exc.errors,
                method=exc.method,
                url=exc.url,
                text=exc.text,
                json=exc.json,
            )
        if any(hint in error_text for hint in _ALREADY_USED_TOKEN_HINTS):
            return exceptions.WrappingTokenAlreadyUsed(
                message="The wrapping token has already been unwrapped and "
                "cannot be used again. Confirm whether the secret was already "
                "retrieved and ask the issuer to re-wrap it if needed.",
                errors=exc.errors,
                method=exc.method,
                url=exc.url,
                text=exc.text,
                json=exc.json,
            )
        detail = exc.args[0] if exc.args else "unknown error"
        return exceptions.WrappingError(
            message=_LOOKUP_REJECTED_MESSAGE.format(
                path=expected_creation_path,
                detail=detail,
            ),
            errors=exc.errors,
            method=exc.method,
            url=exc.url,
            text=exc.text,
            json=exc.json,
        )
