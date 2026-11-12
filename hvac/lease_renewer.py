"""Lease renewal manager for dynamic database credentials.

Vault database secrets engines hand out short-lived SQL accounts together with
a lease.  The lease can be renewed until it reaches its ``max_ttl``; after that
Vault returns a smaller TTL on each renewal and eventually refuses the renewal
altogether.  A robust consumer therefore cannot schedule its renewals from the
TTL of the first response only -- every renewal response may shorten the
remaining lifetime, and the lease may stop being renewable at any time.

This module drives that lifecycle with a small state machine:

* ``renew`` succeeds        -> keep using the current lease, reschedule from
  the TTL returned by *this* response.
* ``renew`` returns a TTL of 0, or Vault reports the lease is gone/not
  renewable -> stop renewing and re-issue a brand-new set of credentials.
* The parent token is revoked (HTTP 403) -> stop sending requests entirely;
  the process has to re-authenticate before anything else can work.
* Transient transport errors (timeouts, connection errors, HTTP 5xx) -> retry
  with backoff while the lease is still alive; if retries are exhausted before
  the safety cutoff, re-issue instead of letting the credentials expire.

Time and sleeping are injected so the whole lifecycle can be exercised with a
fake clock and no background threads.
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional

from hvac import exceptions

logger = logging.getLogger(__name__)


class LeaseState(str, Enum):
    """Lifecycle states of the managed lease."""

    ISSUING = "issuing"
    RENEWING = "renewing"
    REISSUING = "reissuing"
    STOPPED = "stopped"


@dataclass
class LeaseSnapshot:
    """Everything the manager knows about the lease it currently holds."""

    lease_id: str
    ttl: int
    renewable: bool
    entity_id: str
    request_time: float
    expire_time: float
    credentials: Dict[str, Any] = field(default_factory=dict)

    def remaining(self, now: float) -> float:
        return self.expire_time - now


class DatabaseCredentialRenewer:
    """Renew dynamic database-credential leases and re-issue when forced to.

    :param client: A configured ``hvac.Client``.
    :param role: Database role name passed to ``<mount>/creds/<role>``.
    :param mount_point: Mount point of the database secrets engine.
    :param renew_increment: Requested renewal increment (seconds).  Vault may
        grant less once the lease approaches ``max_ttl``.
    :param renew_ratio: Fraction of the *currently granted* TTL to wait before
        renewing again, e.g. ``0.7`` renews at 70% of the granted lifetime.
    :param min_renew_interval: Floor for the computed renewal delay.
    :param retry_backoff: Seconds to wait after a transient renewal failure;
        each consecutive failure doubles the wait.
    :param max_retry_interval: Cap on the exponential backoff.
    :param safety_margin: Retry window before the known expiry.  If the next
        retry would land inside this margin, the lease is given up on and new
        credentials are issued.
    :param clock: Callable returning monotonic-ish time (injectable for tests).
    :param sleep_func: Callable used by :meth:`run` (injectable for tests).
    :param on_credentials: Optional callback invoked with the fresh credential
        payload every time credentials are issued or re-issued.
    """

    def __init__(
        self,
        client,
        role: str,
        mount_point: str = "database",
        renew_increment: int = 3600,
        renew_ratio: float = 0.7,
        min_renew_interval: float = 1.0,
        retry_backoff: float = 2.0,
        max_retry_interval: float = 60.0,
        safety_margin: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        sleep_func: Callable[[float], None] = time.sleep,
        wait_func: Optional[Callable[[float], bool]] = None,
        on_credentials: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.client = client
        self.role = role
        self.mount_point = mount_point
        self.renew_increment = renew_increment
        self.renew_ratio = renew_ratio
        self.min_renew_interval = min_renew_interval
        self.retry_backoff = retry_backoff
        self.max_retry_interval = max_retry_interval
        self.safety_margin = safety_margin
        self._clock = clock
        self._sleep = sleep_func
        self._on_credentials = on_credentials
        # Default to the real stop event; tests inject a fake-clock wait.
        self._wait = wait_func

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self.state = LeaseState.ISSUING
        self.lease: Optional[LeaseSnapshot] = None
        self._next_action_at: Optional[float] = None
        self._failure_count = 0

    # ------------------------------------------------------------------
    # Introspection helpers (what operators and tick() rely on)
    # ------------------------------------------------------------------
    @property
    def next_action_at(self) -> Optional[float]:
        with self._lock:
            return self._next_action_at

    def current_credentials(self) -> Dict[str, Any]:
        """Return the credential payload the app should use right now."""
        with self._lock:
            return dict(self.lease.credentials) if self.lease else {}

    def stop(self) -> None:
        """Ask :meth:`run` to exit; in-flight HTTP calls are not cancelled."""
        self._stop.set()
        with self._lock:
            self._next_action_at = self._clock()
        logger.info("lease.renewer.stop_requested role=%s", self.role)

    def _wait_or_stop(self, seconds: float) -> bool:
        """Wait up to ``seconds``; return True if :meth:`stop` was requested."""
        if self._wait is not None:
            return self._wait(seconds)
        return self._stop.wait(timeout=seconds)

    # ------------------------------------------------------------------
    # Vault operations (thin wrappers, easy to stub in tests)
    # ------------------------------------------------------------------
    def _issue_credentials(self) -> Dict[str, Any]:
        return self.client.secrets.database.generate_credentials(
            name=self.role, mount_point=self.mount_point
        )

    def _renew_lease(self, lease_id: str) -> Dict[str, Any]:
        return self.client.sys.renew_lease(
            lease_id=lease_id, increment=self.renew_increment
        )

    def _revoke_lease(self, lease_id: str) -> None:
        try:
            self.client.sys.revoke_lease(lease_id=lease_id)
        except Exception:
            logger.warning(
                "lease.revoke.failed lease_id=%s role=%s", lease_id, self.role, exc_info=True
            )

    # ------------------------------------------------------------------
    # Issue / re-issue
    # ------------------------------------------------------------------
    def issue(self) -> LeaseSnapshot:
        """Fetch a fresh set of credentials and adopt its lease."""
        with self._lock:
            previous = self.lease
            self.state = LeaseState.REISSUING if previous else LeaseState.ISSUING
        logger.info(
            "lease.issue.start role=%s mount=%s reason=%s",
            self.role,
            self.mount_point,
            "initial" if previous is None else "lease_exhausted",
        )
        try:
            response = self._issue_credentials()
        except exceptions.Forbidden as exc:
            with self._lock:
                self.state = LeaseState.STOPPED
                self._next_action_at = None
            logger.error(
                "lease.issue.parent_token_revoked event=lease.renewer.halted "
                "role=%s error=%s -- stop issuing requests; "
                "re-authenticate and restart",
                self.role,
                exc,
            )
            raise
        snapshot = self._snapshot_from_lease_response(response)
        with self._lock:
            self.lease = snapshot
            self._failure_count = 0
            self.state = LeaseState.RENEWING
            self._schedule_next_renewal(snapshot.request_time, snapshot.ttl)
        if previous is not None and previous.lease_id != snapshot.lease_id:
            self._revoke_lease(previous.lease_id)
        logger.info(
            "lease.issue.success event=lease.reissued lease_id=%s ttl=%s expire_at=%.1f role=%s",
            snapshot.lease_id,
            snapshot.ttl,
            snapshot.expire_time,
            self.role,
        )
        if self._on_credentials is not None:
            self._on_credentials(dict(snapshot.credentials))
        return snapshot

    def _snapshot_from_lease_response(self, response: Dict[str, Any]) -> LeaseSnapshot:
        data = response.get("data", {}) or {}
        now = self._clock()
        ttl = int(response.get("lease_duration", 0) or 0)
        renewable = bool(response.get("renewable", False))
        return LeaseSnapshot(
            lease_id=response["lease_id"],
            ttl=ttl,
            renewable=renewable,
            entity_id=str(data.get("username", "")),
            request_time=now,
            expire_time=now + ttl,
            credentials={
                "username": data.get("username"),
                "password": data.get("password"),
            },
        )

    # ------------------------------------------------------------------
    # Renewal
    # ------------------------------------------------------------------
    def renew_once(self) -> Optional[LeaseSnapshot]:
        """Attempt a single renewal.

        Returns the updated lease on success, or ``None`` when a retry is
        pending after a transient failure.  Raises
        :class:`hvac.exceptions.Forbidden` when the parent token is revoked;
        the renewer is then in the ``stopped`` state and emits no more
        requests.
        """
        with self._lock:
            lease = self.lease
        if lease is None:
            return self.issue()

        now = self._clock()
        if not lease.renewable:
            logger.warning(
                "lease.renew.not_renewable event=lease.reissue_starting "
                "lease_id=%s role=%s",
                lease.lease_id,
                self.role,
            )
            return self._reissue_or_retry(lease, now)

        try:
            response = self._renew_lease(lease.lease_id)
        except exceptions.Forbidden as exc:
            # Parent token revoked / no capability: no amount of retrying will
            # help, and we must stop hammering Vault.
            with self._lock:
                self.state = LeaseState.STOPPED
                self._next_action_at = None
            logger.error(
                "lease.renew.parent_token_revoked event=lease.renewer.halted "
                "lease_id=%s role=%s error=%s -- stop issuing requests; "
                "re-authenticate and restart",
                lease.lease_id,
                self.role,
                exc,
            )
            raise
        except (exceptions.InvalidPath, exceptions.InvalidRequest) as exc:
            # Vault answers "lease not found"/"lease is not renewable" with
            # 404 or 400.  The lease is gone: re-issue immediately, no retry.
            if self._is_terminal_lease_error(exc):
                logger.warning(
                    "lease.renew.lease_not_found event=lease.reissue_starting "
                    "lease_id=%s role=%s error=%s",
                    lease.lease_id,
                    self.role,
                    exc,
                )
                return self._reissue_or_retry(lease, now)
            return self._handle_transient_failure(lease, exc, now)
        except exceptions.VaultError as exc:
            return self._handle_transient_failure(lease, exc, now)
        except Exception as exc:  # requests.ConnectionError, Timeout, ...
            return self._handle_transient_failure(lease, exc, now)

        return self._apply_renewal_response(lease, response, now)

    def _apply_renewal_response(
        self, lease: LeaseSnapshot, response: Dict[str, Any], now: float
    ) -> LeaseSnapshot:
        granted_ttl = int(response.get("lease_duration", 0) or 0)
        renewable = bool(response.get("renewable", lease.renewable))
        with self._lock:
            lease.request_time = now
            lease.ttl = granted_ttl
            lease.renewable = renewable
            lease.expire_time = now + granted_ttl
            self._failure_count = 0
            self.state = LeaseState.RENEWING
            self._schedule_next_renewal(now, granted_ttl)

        if granted_ttl <= 0 or not renewable:
            logger.warning(
                "lease.renew.max_ttl_reached event=lease.reissue_starting "
                "lease_id=%s granted_ttl=%s renewable=%s role=%s",
                lease.lease_id,
                granted_ttl,
                renewable,
                self.role,
            )
            return self._reissue_or_retry(lease, now)

        logger.info(
            "lease.renew.success event=lease.renewed lease_id=%s "
            "granted_ttl=%s expire_at=%.1f next_renew_at=%.1f role=%s",
            lease.lease_id,
            granted_ttl,
            lease.expire_time,
            self._next_action_at,
            self.role,
        )
        return lease

    def _handle_transient_failure(
        self, lease: LeaseSnapshot, exc: Exception, now: float
    ) -> Optional[LeaseSnapshot]:
        self._failure_count += 1
        attempt = self._failure_count
        backoff = min(self.max_retry_interval, self.retry_backoff * 2 ** (attempt - 1))
        retry_at = now + backoff
        cutoff = lease.expire_time - self.safety_margin

        if retry_at >= cutoff:
            logger.error(
                "lease.renew.retry_exhausted event=lease.reissue_starting "
                "lease_id=%s attempt=%s expire_at=%.1f role=%s error=%r",
                lease.lease_id,
                attempt,
                lease.expire_time,
                self.role,
                exc,
            )
            return self._reissue_or_retry(lease, now, trigger_error=exc)

        with self._lock:
            self._next_action_at = retry_at
        logger.warning(
            "lease.renew.transient_failure event=lease.renew_retry_scheduled "
            "lease_id=%s attempt=%s retry_at=%.1f expire_at=%.1f role=%s error=%r",
            lease.lease_id,
            attempt,
            retry_at,
            lease.expire_time,
            self.role,
            exc,
        )
        return None

    def _reissue_or_retry(
        self,
        lease: LeaseSnapshot,
        now: float,
        trigger_error: Optional[Exception] = None,
    ) -> Optional[LeaseSnapshot]:
        """Re-issue credentials; on a transient failure, retry with backoff."""
        try:
            return self.issue()
        except exceptions.Forbidden:
            raise
        except Exception as exc:
            if trigger_error is not None:
                logger.warning(
                    "lease.issue.failed_after_renewal_failure lease_id=%s "
                    "renewal_error=%r issue_error=%r role=%s",
                    lease.lease_id,
                    trigger_error,
                    exc,
                    self.role,
                )
            return self._handle_transient_failure(lease, exc, now)

    def _schedule_next_renewal(self, now: float, granted_ttl: int) -> None:
        if granted_ttl <= 0:
            self._next_action_at = now
            return
        delay = max(self.min_renew_interval, granted_ttl * self.renew_ratio)
        self._next_action_at = now + delay

    @staticmethod
    def _is_terminal_lease_error(exc: Exception) -> bool:
        if isinstance(exc, exceptions.InvalidPath):
            return True
        message = str(exc).lower()
        return "not found" in message or "not renewable" in message

    # ------------------------------------------------------------------
    # Clock-driven loop
    # ------------------------------------------------------------------
    def tick(self) -> bool:
        """Run one due action. Returns False once the renewer has halted."""
        if self._stop.is_set():
            with self._lock:
                self.state = LeaseState.STOPPED
            return False
        with self._lock:
            if self.state == LeaseState.STOPPED:
                return False
            due = self._next_action_at is None or self._clock() >= self._next_action_at
        if not due:
            return True
        self.renew_once()
        with self._lock:
            return self.state != LeaseState.STOPPED

    def run(self) -> None:
        """Block, driving renewals until :meth:`stop` or a fatal error."""
        if self.lease is None:
            self._issue_with_retry()
        while not self._stop.is_set():
            with self._lock:
                if self.state == LeaseState.STOPPED:
                    logger.error(
                        "lease.renewer.halted event=lease.renewer.stopped role=%s",
                        self.role,
                    )
                    return
                action_at = self._next_action_at
                now = self._clock()
            sleep_for = 0.0 if action_at is None else max(0.0, action_at - now)
            sleep_for = max(sleep_for, self.min_renew_interval)
            if self._wait_or_stop(sleep_for):
                break
            try:
                self.tick()
            except exceptions.Forbidden:
                return
        with self._lock:
            self.state = LeaseState.STOPPED
        logger.info("lease.renewer.stopped event=lease.renewer.stopped role=%s", self.role)

    def _issue_with_retry(self) -> None:
        """Initial issue with backoff so a cold-start outage does not crash run()."""
        attempt = 0
        while not self._stop.is_set():
            try:
                self.issue()
                return
            except exceptions.Forbidden:
                raise
            except Exception as exc:
                attempt += 1
                backoff = min(
                    self.max_retry_interval, self.retry_backoff * 2 ** (attempt - 1)
                )
                logger.warning(
                    "lease.issue.transient_failure event=lease.issue_retry_scheduled "
                    "attempt=%s retry_in=%.1f role=%s error=%r",
                    attempt,
                    backoff,
                    self.role,
                    exc,
                )
                if self._wait_or_stop(backoff):
                    return
