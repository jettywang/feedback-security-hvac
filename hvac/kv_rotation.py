"""Reusable, race-safe secret rotation flow for KV v2.

This module implements an explicit check-and-set (CAS) rotation flow on top of
:class:`hvac.api.secrets_engines.kv_v2.KvV2`. It is designed for rotation jobs
that must never silently overwrite a value written by a concurrent job:

* The current version is read once and written back with an explicit ``cas``
  parameter. A lost race surfaces as :class:`RotationConflictError`; the flow
  never re-reads the old value and retries on its own.
* Soft-deleted, destroyed, and never-created keys are distinguished via
  :class:`KeyState`, and the caller decides (via ``allow_states``) which states
  may be rotated.
* Every conflict and rejected state is emitted as an :class:`AuditRecord`
  containing only the key path, the version number, and the conflict reason.
"""

import enum
import logging
import typing
from collections import namedtuple

from hvac import exceptions
from hvac.api.secrets_engines.kv_v2 import DEFAULT_MOUNT_POINT

audit_logger = logging.getLogger("hvac.kv_rotation.audit")


class KeyState(enum.Enum):
    """Lifecycle state of a KV v2 key at rotation time."""

    ACTIVE = "active"
    SOFT_DELETED = "soft_deleted"
    DESTROYED = "destroyed"
    NEVER_CREATED = "never_created"


#: An audit record for a rotation conflict. Carries exactly the key path, the
#: version number (``None`` when the key was never created), and the reason.
AuditRecord = namedtuple("AuditRecord", ["path", "version", "reason"])


class RotationError(Exception):
    """Base class for rotation flow failures."""


class RotationStateError(RotationError):
    """The key is in a state the caller did not allow; no write was attempted.

    :ivar path: Path of the key.
    :ivar state: The observed :class:`KeyState`.
    :ivar version: The version observed at read time (``None`` if never created).
    """

    def __init__(self, path, state, version):
        self.path = path
        self.state = state
        self.version = version
        super().__init__(
            f"refusing to rotate {path!r}: key state is {state.value} "
            f"(version={version}); pass allow_states to permit it"
        )


class RotationConflictError(RotationError):
    """The CAS write was rejected; a concurrent writer (or deleter) won the race.

    Carries everything needed to decide the next step without this flow having
    re-read anything: the caller may re-run :func:`rotate_secret` from scratch
    (a fresh read) or abort.

    :ivar path: Path of the key.
    :ivar version: The version the CAS write was based on.
    :ivar reason: The conflict reason reported by Vault.
    """

    def __init__(self, path, version, reason):
        self.path = path
        self.version = version
        self.reason = reason
        super().__init__(
            f"CAS conflict rotating {path!r} at version={version}: {reason}"
        )


def _default_audit(record):
    audit_logger.info(
        "rotation conflict: path=%s version=%s reason=%s",
        record.path,
        record.version,
        record.reason,
    )


def _emit(audit, record):
    (audit or _default_audit)(record)


def _inspect(kv, path, mount_point):
    """Read the key once and classify its state.

    :return: (state, version, data) where data is the secret dict or None.
    """
    try:
        response = kv.read_secret_version(
            path=path,
            mount_point=mount_point,
            raise_on_deleted_version=False,
        )
    except exceptions.InvalidPath:
        return KeyState.NEVER_CREATED, None, None

    metadata = response["data"]["metadata"]
    version = metadata["version"]
    if metadata.get("destroyed"):
        return KeyState.DESTROYED, version, None
    if metadata.get("deletion_time"):
        return KeyState.SOFT_DELETED, version, None
    return KeyState.ACTIVE, version, response["data"].get("data")


def rotate_secret(
    kv,
    path,
    rotate,
    *,
    mount_point=DEFAULT_MOUNT_POINT,
    allow_states=frozenset({KeyState.ACTIVE}),
    audit=None,
):
    """Rotate the secret at ``path`` using an explicit CAS write.

    The flow is exactly: one read, caller-supplied transformation, one CAS
    write. There is deliberately no automatic retry: if the CAS write loses a
    race, :class:`RotationConflictError` is raised with the path, the version
    the write was based on, and Vault's reason, so the caller can decide
    whether to start over with a fresh read.

    :param kv: A :class:`hvac.api.secrets_engines.kv_v2.KvV2` instance (or the
        ``client.secrets.kv.v2`` facade).
    :param path: Path of the secret to rotate.
    :param rotate: Callable receiving the current secret dict (``None`` when
        the key was never created or its data is unreadable) and returning the
        new secret dict.
    :param mount_point: The mount point of the KV v2 engine.
    :param allow_states: Set of :class:`KeyState` values that may be rotated.
        Soft-deleted, destroyed, and never-created keys are rejected with
        :class:`RotationStateError` unless explicitly allowed here. A
        never-created key, when allowed, is created with ``cas=0``.
    :param audit: Optional callable receiving an :class:`AuditRecord` for each
        conflict or rejected state. Defaults to the ``hvac.kv_rotation.audit``
        logger.
    :return: The JSON response of the successful write.
    :raises RotationStateError: The key's state is not in ``allow_states``.
    :raises RotationConflictError: The CAS write was rejected.
    """
    state, version, current = _inspect(kv, path, mount_point)

    if state not in allow_states:
        reason = f"key state is {state.value}; rotation not allowed"
        _emit(audit, AuditRecord(path=path, version=version, reason=reason))
        raise RotationStateError(path=path, state=state, version=version)

    new_secret = rotate(current)

    # cas=0 creates the key only if it still does not exist; otherwise the CAS
    # pins the write to the exact version we read.
    cas = 0 if state is KeyState.NEVER_CREATED else version
    try:
        return kv.create_or_update_secret(
            path=path,
            secret=new_secret,
            cas=cas,
            mount_point=mount_point,
        )
    except exceptions.InvalidRequest as error:
        reason = str(error.args[0]) if error.args else "cas mismatch"
        _emit(audit, AuditRecord(path=path, version=version, reason=reason))
        raise RotationConflictError(path=path, version=version, reason=reason) from error
