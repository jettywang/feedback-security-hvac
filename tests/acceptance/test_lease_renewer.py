"""Local acceptance tests for the dynamic-DB-credential lease renewer.

No Vault server is required: a fake clock and a scripted fake Vault drive the
renewer through the four operational scenarios:

1. max_ttl: a renewal comes back with a shorter, then zero TTL.
2. lease not found: renewal returns HTTP 400 ``lease not found``.
3. parent token revoked: renewal returns HTTP 403 and the renewer halts.
4. timeout followed by real success: transport errors are retried with
   backoff until a renewal finally succeeds.

Run with::

    .venv/bin/python -m pytest tests/acceptance/test_lease_renewer.py -v -s
"""

import logging
import threading
import time

import pytest

from hvac import exceptions
from hvac.lease_renewer import DatabaseCredentialRenewer, LeaseState


class FakeClock:
    """Deterministic clock: time only moves when sleep() is called."""

    def __init__(self, start=1_000_000.0):
        self.now = start

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += max(0.0, seconds)


class FakeVault:
    """Scripted Vault: queue renewal responses/errors per lease id."""

    def __init__(self, clock, issue_ttl=3600):
        self.clock = clock
        self.issue_ttl = issue_ttl
        self.renewal_scripts = {}
        self.issue_calls = 0
        self.renew_calls = []
        self.revoked = []
        self.always_renewable = False
        self._counter = 0

    def next_lease_id(self):
        self._counter += 1
        return f"database/creds/app/{self._counter:08d}"

    def issue_response(self, ttl=None, renewable=True):
        self.issue_calls += 1
        lease_id = self.next_lease_id()
        ttl = self.issue_ttl if ttl is None else ttl
        return {
            "lease_id": lease_id,
            "lease_duration": ttl,
            "renewable": renewable,
            "data": {"username": f"v-appuser-{self._counter}", "password": "pw"},
        }

    def renew_response(self, ttl, renewable=True):
        return {"lease_duration": ttl, "renewable": renewable}

    def error(self, status_code, message="mock failure"):
        return exceptions.VaultError.from_status(status_code, message)

    # -- renewer-facing API ------------------------------------------------
    def generate_credentials(self, name, mount_point):
        return self.issue_response()

    def renew_lease(self, lease_id, increment):
        self.renew_calls.append((self.clock.time() if self.clock else None, lease_id))
        if self.always_renewable:
            return {"lease_duration": self.issue_ttl, "renewable": True}
        script = self.renewal_scripts.setdefault(lease_id, [])
        if not script:
            raise AssertionError(f"unexpected renewal for {lease_id}")
        action = script.pop(0)
        if isinstance(action, Exception):
            raise action
        return action

    def revoke_lease(self, lease_id):
        self.revoked.append(lease_id)


class FakeSecrets:
    def __init__(self, vault):
        self.database = vault


class FakeSys:
    def __init__(self, vault):
        self._vault = vault

    def renew_lease(self, lease_id, increment=None):
        return self._vault.renew_lease(lease_id, increment)

    def revoke_lease(self, lease_id):
        return self._vault.revoke_lease(lease_id)


class FakeClient:
    def __init__(self, vault):
        self.secrets = FakeSecrets(vault)
        self.sys = FakeSys(vault)


def build_renewer(vault, clock, **kwargs):
    client = FakeClient(vault)
    defaults = dict(
        role="app",
        mount_point="database",
        renew_increment=3600,
        renew_ratio=0.5,
        min_renew_interval=1.0,
        retry_backoff=2.0,
        max_retry_interval=60.0,
        safety_margin=30.0,
        clock=clock.time,
        sleep_func=clock.sleep,
        # A "wait" simply advances the fake clock, so run() never blocks.
        wait_func=lambda seconds: (clock.sleep(seconds), False)[1],
    )
    defaults.update(kwargs)
    return DatabaseCredentialRenewer(client=client, **defaults)


def run_until_state(renewer, clock, states, max_ticks=50):
    """Drive run-loop iterations (sleep advances the fake clock) until state."""
    for _ in range(max_ticks):
        if renewer.state in states:
            return
        renewer.tick()
        if renewer.next_action_at is not None:
            clock.sleep(max(0.0, renewer.next_action_at - clock.time()))
    raise AssertionError(f"never reached {states}, state={renewer.state}")


@pytest.fixture(autouse=True)
def _renewer_log_level(caplog):
    caplog.set_level(logging.INFO, logger="hvac.lease_renewer")


def test_max_ttl_shorter_ttl_then_reissue(caplog):
    clock = FakeClock()
    vault = FakeVault(clock, issue_ttl=3600)
    renewer = build_renewer(vault, clock)

    first = renewer.issue()
    assert first.ttl == 3600
    assert renewer.state == LeaseState.RENEWING

    # Renewal 1: max_ttl caps the grant well below the requested increment.
    vault.renewal_scripts[first.lease_id] = [
        vault.renew_response(ttl=600),
        vault.renew_response(ttl=0, renewable=False),
    ]
    renewed = renewer.renew_once()
    assert renewed.lease_id == first.lease_id
    assert renewed.ttl == 600
    # Timer must follow the *new* TTL, not the original 3600.
    assert renewer.next_action_at == clock.time() + 300
    assert any("lease.renew.success" in r.message for r in caplog.records)

    # Renewal 2: lease hit max_ttl, Vault returns TTL 0 -> re-issue.
    replaced = renewer.renew_once()
    assert replaced.lease_id != first.lease_id
    assert renewer.state == LeaseState.RENEWING
    assert vault.issue_calls == 2
    assert vault.revoked == [first.lease_id]
    assert any("lease.renew.max_ttl_reached" in r.message for r in caplog.records)
    assert any("lease.reissued" in r.message for r in caplog.records)
    assert renewer.current_credentials()["username"] == replaced.entity_id


def test_lease_not_found_triggers_reissue_without_retry(caplog):
    clock = FakeClock()
    vault = FakeVault(clock)
    renewer = build_renewer(vault, clock)
    lease = renewer.issue()

    vault.renewal_scripts[lease.lease_id] = [
        vault.error(400, "lease not found")
    ]
    replaced = renewer.renew_once()

    assert replaced.lease_id != lease.lease_id
    assert vault.issue_calls == 2
    assert len(vault.renew_calls) == 1  # no retry on a dead lease
    assert vault.revoked == [lease.lease_id]
    assert any(
        "lease.renew.lease_not_found" in r.message for r in caplog.records
    )
    assert renewer.state == LeaseState.RENEWING


def test_parent_token_revocation_halts_and_stops_requests(caplog):
    clock = FakeClock()
    vault = FakeVault(clock)
    renewer = build_renewer(vault, clock)
    lease = renewer.issue()

    vault.renewal_scripts[lease.lease_id] = [vault.error(403, "permission denied")]
    with pytest.raises(exceptions.Forbidden):
        renewer.renew_once()

    assert renewer.state == LeaseState.STOPPED
    assert renewer.next_action_at is None
    # tick() must not send any further Vault traffic.
    renew_calls_before = len(vault.renew_calls)
    issue_calls_before = vault.issue_calls
    assert renewer.tick() is False
    assert len(vault.renew_calls) == renew_calls_before
    assert vault.issue_calls == issue_calls_before
    assert any(
        "lease.renew.parent_token_revoked" in r.message for r in caplog.records
    )
    assert any("lease.renewer.halted" in r.message for r in caplog.records)


def test_timeout_then_renewal_eventually_succeeds(caplog):
    clock = FakeClock()
    vault = FakeVault(clock, issue_ttl=3600)
    renewer = build_renewer(vault, clock)
    lease = renewer.issue()
    original_expiry = lease.expire_time

    # Two timeouts, then a successful renewal.
    vault.renewal_scripts[lease.lease_id] = [
        exceptions.UnexpectedError("read timed out"),
        exceptions.UnexpectedError("connection reset"),
        vault.renew_response(ttl=1800),
    ]

    first = renewer.renew_once()  # timeout -> scheduled retry, lease retained
    assert first is None
    assert renewer.lease.lease_id == lease.lease_id
    first_retry_at = renewer.next_action_at
    assert any(
        "lease.renew_retry_scheduled" in r.message for r in caplog.records
    )

    clock.sleep(first_retry_at - clock.time())
    second = renewer.renew_once()  # second timeout, exponential backoff
    assert second is None
    assert renewer.next_action_at > first_retry_at

    clock.sleep(renewer.next_action_at - clock.time())
    recovered = renewer.renew_once()  # success
    assert recovered.lease_id == lease.lease_id
    assert recovered.ttl == 1800
    assert vault.issue_calls == 1  # never re-issued: existing lease survived
    assert len(vault.renew_calls) == 3
    assert any("lease.renew.success" in r.message for r in caplog.records)
    # Timer follows the freshly granted TTL.
    assert renewer.next_action_at == clock.time() + 900
    assert original_expiry != recovered.expire_time


def test_transient_failures_past_cutoff_force_reissue(caplog):
    clock = FakeClock()
    vault = FakeVault(clock, issue_ttl=10)
    renewer = build_renewer(vault, clock, safety_margin=30.0)
    lease = renewer.issue()

    vault.renewal_scripts[lease.lease_id] = [
        exceptions.UnexpectedError("read timed out"),
    ]
    replaced = renewer.renew_once()

    # retry_at (now+2) >= expire(10s) - margin(30s) -> re-issue immediately.
    assert replaced.lease_id != lease.lease_id
    assert vault.issue_calls == 2
    assert any("lease.renew.retry_exhausted" in r.message for r in caplog.records)


def test_reissue_failure_falls_back_to_retry(caplog):
    clock = FakeClock()
    vault = FakeVault(clock)
    renewer = build_renewer(vault, clock)
    lease = renewer.issue()

    # Lease is gone, and the replacement issue call also times out once.
    vault.renewal_scripts[lease.lease_id] = [
        vault.error(400, "lease not found")
    ]
    original_issue = vault.issue_response
    vault.issue_response = lambda *a, **k: (_ for _ in ()).throw(
        exceptions.UnexpectedError("issue timed out")
    )
    result = renewer.renew_once()
    assert result is None
    assert renewer.lease.lease_id == lease.lease_id  # old lease retained
    assert any(
        "lease.renew_retry_scheduled" in r.message for r in caplog.records
    )

    # Next attempt: re-issue succeeds and replaces the dead lease.
    vault.issue_response = original_issue
    vault.renewal_scripts[lease.lease_id] = [
        vault.error(400, "lease not found")
    ]
    clock.sleep(renewer.next_action_at - clock.time())
    replaced = renewer.renew_once()
    assert replaced.lease_id != lease.lease_id
    assert renewer.state == LeaseState.RENEWING


def test_run_loop_renews_on_each_returned_ttl_then_stops(caplog):
    clock = FakeClock()
    vault = FakeVault(clock, issue_ttl=100)
    renewer = build_renewer(vault, clock, renew_ratio=0.5)

    lease = renewer.issue()
    vault.renewal_scripts[lease.lease_id] = [
        vault.renew_response(ttl=50),
        vault.renew_response(ttl=10),
    ]

    # Drive two scheduled renewals through tick() using the fake clock.
    clock.sleep(renewer.next_action_at - clock.time())
    renewer.tick()
    assert renewer.lease.ttl == 50
    assert renewer.next_action_at == clock.time() + 25

    clock.sleep(renewer.next_action_at - clock.time())
    renewer.tick()
    assert renewer.lease.ttl == 10
    assert renewer.next_action_at == clock.time() + 5
    assert len(vault.renew_calls) == 2

    # stop() halts the loop and tick() emits no further Vault requests.
    renewer.stop()
    assert renewer.tick() is False
    assert renewer.state == LeaseState.STOPPED
    assert len(vault.renew_calls) == 2
    assert any("lease.renewer.stop_requested" in r.message for r in caplog.records)


def test_run_loop_in_thread_renews_and_stops():
    # Real clock and real stop event: run() blocks on threading.Event between
    # actions, exactly as it would in production.
    vault = FakeVault(clock=None, issue_ttl=1)
    vault.always_renewable = True
    client = FakeClient(vault)
    renewer = DatabaseCredentialRenewer(
        client=client,
        role="app",
        renew_ratio=0.5,
        min_renew_interval=0.05,
        safety_margin=0.1,
    )
    thread = threading.Thread(target=renewer.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and len(vault.renew_calls) < 3:
            time.sleep(0.02)
        assert len(vault.renew_calls) >= 3
        assert renewer.state == LeaseState.RENEWING
        assert renewer.current_credentials()["username"]
    finally:
        renewer.stop()
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert renewer.state == LeaseState.STOPPED


def test_run_loop_halts_on_parent_token_revocation():
    clock = FakeClock()
    vault = FakeVault(clock)
    renewer = build_renewer(vault, clock)
    lease = renewer.issue()
    vault.renewal_scripts[lease.lease_id] = [vault.error(403, "permission denied")]

    # run() returns immediately rather than spinning after the fatal 403.
    renewer.run()
    assert renewer.state == LeaseState.STOPPED
    assert len(vault.renew_calls) == 1
