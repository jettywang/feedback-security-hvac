class VaultError(Exception):
    def __init__(
        self, message=None, errors=None, method=None, url=None, text=None, json=None
    ):
        if errors:
            message = ", ".join(errors)

        self.errors = errors
        self.method = method
        self.url = url
        self.text = text
        self.json = json

        super().__init__(message)

    def __str__(self):
        return f"{self.args[0]}, on {self.method} {self.url}"

    @classmethod
    def from_status(cls, status_code: int, *args, **kwargs):
        _STATUS_EXCEPTION_MAP = {
            400: InvalidRequest,
            401: Unauthorized,
            403: Forbidden,
            404: InvalidPath,
            429: RateLimitExceeded,
            500: InternalServerError,
            501: VaultNotInitialized,
            502: BadGateway,
            503: VaultDown,
        }

        return _STATUS_EXCEPTION_MAP.get(status_code, UnexpectedError)(*args, **kwargs)


class InvalidRequest(VaultError):
    pass


class Unauthorized(VaultError):
    pass


class Forbidden(VaultError):
    pass


class InvalidPath(VaultError):
    pass


class UnsupportedOperation(VaultError):
    pass


class PreconditionFailed(VaultError):
    pass


class RateLimitExceeded(VaultError):
    pass


class InternalServerError(VaultError):
    pass


class VaultNotInitialized(VaultError):
    pass


class VaultDown(VaultError):
    pass


class UnexpectedError(VaultError):
    pass


class BadGateway(VaultError):
    pass


class ParamValidationError(VaultError):
    pass


class WrappingError(VaultError):
    """Base class for errors encountered while handling response wrapping tokens."""


class WrappingTokenExpired(WrappingError):
    """Raised when the wrapping token has expired or is no longer valid.

    The wrapped secret was never handed out. Ask the issuer to wrap the secret
    again and provide a fresh wrapping token.
    """


class WrappingTokenAlreadyUsed(WrappingError):
    """Raised when the wrapping token has already been unwrapped.

    A wrapping token can only be unwrapped once. The secret may already have
    been retrieved, so contact the issuer to re-wrap the secret instead of
    retrying with this token.
    """


class WrappingPathMismatch(WrappingError):
    """Raised when the token's creation path does not match the expected path.

    This check does not consume the wrapping token. Do not unwrap the token:
    verify its provenance with the issuer and reject tokens created on an
    unexpected path.
    """

    def __init__(self, message=None, expected_path=None, actual_path=None, **kwargs):
        self.expected_path = expected_path
        self.actual_path = actual_path
        super().__init__(message, **kwargs)


class WrappingResultUnknown(WrappingError):
    """Raised when the outcome of an unwrap request cannot be determined.

    The request reached Vault (or may have), but no definitive response was
    received. The wrapping token is single-use, so retrying blindly cannot prove
    whether the secret was exposed. Use a separate, non-wrapping capability such
    as ``auth/token/lookup`` or the wrapped secret's own identifier to check the
    outcome, and ask the issuer to re-wrap the secret if it cannot be confirmed.
    """
