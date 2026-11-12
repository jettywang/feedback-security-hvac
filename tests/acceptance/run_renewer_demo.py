#!/usr/bin/env python3
"""Runnable, dependency-free demo of the lease-renewal state machine.

Uses a fake clock and a scripted in-memory Vault (no network, no real Vault).
Each scenario prints the structured log lines an operator would see in
production, showing when the process keeps using the current lease and when it
stops sending requests.

Run::

    .venv/bin/python tests/acceptance/run_renewer_demo.py
"""

import logging
import sys

from hvac import exceptions
from hvac.lease_renewer import DatabaseCredentialRenewer


class FakeClock:
    def __init__(self, start=1_000_000.0):
        self.now = start

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += max(0.0, seconds)


class FakeVault:
    def __init__(self, clock):
        self.clock = clock
        self.scripts = {}
        self.issued = 0
        self.renewals = 0
        self.revoked = []
        self._n = 0

    def _lease_id(self):
        self._n += 1
        return f"database/creds/app/{self._n:08d}"

    def issue(self, name, mount_point):
        self.issued += 1
        lease_id = self._lease_id()
        return {
            "lease_id": lease_id,
            "lease_duration": 3600,
            "renewable": True,
            "data": {"username": f"v-appuser-{self._n}", "password": "secret"},
        }

    def renew(self, lease_id, increment):
        self.renewals += 1
        action = self.scripts[lease_id].pop(0)
        if isinstance(action, Exception):
            raise action
        return action

    def revoke(self, lease_id):
        self.revoked.append(lease_id)


class _Database:
    def __init__(self, vault):
        self._vault = vault

    def generate_credentials(self, name, mount_point):
        return self._vault.issue(name, mount_point)


class _Secrets:
    def __init__(self, vault):
        self.database = _Database(vault)


class _Sys:
    def __init__(self, vault):
        self._vault = vault

    def renew_lease(self, lease_id, increment=None):
        return self._vault.renew(lease_id, increment)

    def revoke_lease(self, lease_id):
        self._vault.revoke(lease_id)


class FakeClient:
    def __init__(self, vault):
        self.secrets = _Secrets(vault)
        self.sys = _Sys(vault)


def make_renewer(vault, clock):
    return DatabaseCredentialRenewer(
        client=FakeClient(vault),
        role="app",
        renew_increment=3600,
        renew_ratio=0.5,
        safety_margin=30.0,
        clock=clock.time,
        sleep_func=clock.sleep,
    )


def banner(title):
    print("\n" + "=" * 78)
    print(f"  {title}")
    print("=" * 78)


def show_state(label, renewer):
    lease = renewer.lease
    print(
        f"[{label}] state={renewer.state.value:9s} "
        f"lease={lease.lease_id if lease else '-'} "
        f"ttl={lease.ttl if lease else '-'} "
        f"next_action_at={renewer.next_action_at} "
        f"user={renewer.current_credentials().get('username')}"
    )


def scenario_max_ttl():
    banner("1) max TTL: shorter TTL granted, then TTL 0 -> re-issue")
    clock = FakeClock()
    vault = FakeVault(clock)
    renewer = make_renewer(vault, clock)

    lease = renewer.issue()
    vault.scripts[lease.lease_id] = [
        {"lease_duration": 600, "renewable": True},
        {"lease_duration": 0, "renewable": False},
    ]
    show_state("issued ", renewer)

    renewer.renew_once()
    show_state("renew 1", renewer)
    print("  -> kept using the SAME lease; timer rescheduled from the new 600s TTL")

    renewer.renew_once()
    show_state("renew 2", renewer)
    print(f"  -> lease exhausted; new credentials issued (issue calls={vault.issued})")


def scenario_lease_not_found():
    banner("2) lease not found (HTTP 400) -> immediate re-issue, no retry")
    clock = FakeClock()
    vault = FakeVault(clock)
    renewer = make_renewer(vault, clock)
    lease = renewer.issue()
    vault.scripts[lease.lease_id] = [
        exceptions.VaultError.from_status(400, "lease not found")
    ]
    renewer.renew_once()
    show_state("result ", renewer)
    print(f"  -> renewal attempts for dead lease: {vault.renewals}; re-issued: {vault.issued}")


def scenario_parent_token_revoked():
    banner("3) parent token revoked (HTTP 403) -> halt, stop all requests")
    clock = FakeClock()
    vault = FakeVault(clock)
    renewer = make_renewer(vault, clock)
    lease = renewer.issue()
    vault.scripts[lease.lease_id] = [
        exceptions.VaultError.from_status(403, "permission denied")
    ]
    try:
        renewer.renew_once()
    except exceptions.Forbidden:
        pass
    show_state("result ", renewer)
    before = (vault.issued, vault.renewals)
    renewer.tick()
    after = (vault.issued, vault.renewals)
    print(f"  -> tick() after halt issued no traffic: {before == after}")
    print("  -> operator must re-authenticate (new token) and restart the process")


def scenario_timeout_then_success():
    banner("4) timeouts with backoff, then renewal succeeds -> keep lease")
    clock = FakeClock()
    vault = FakeVault(clock)
    renewer = make_renewer(vault, clock)
    lease = renewer.issue()
    vault.scripts[lease.lease_id] = [
        exceptions.UnexpectedError("read timed out"),
        exceptions.UnexpectedError("connection reset by peer"),
        {"lease_duration": 1800, "renewable": True},
    ]
    renewer.renew_once()
    show_state("retry 1", renewer)
    clock.sleep(renewer.next_action_at - clock.time())
    renewer.renew_once()
    show_state("retry 2", renewer)
    clock.sleep(renewer.next_action_at - clock.time())
    renewer.renew_once()
    show_state("success", renewer)
    print(f"  -> same lease retained throughout; issue calls={vault.issued}, renewals={vault.renewals}")


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        stream=sys.stdout,
    )
    scenario_max_ttl()
    scenario_lease_not_found()
    scenario_parent_token_revoked()
    scenario_timeout_then_success()
    banner("done")


if __name__ == "__main__":
    main()
