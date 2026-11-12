Dynamic Credential Lease Renewal
================================

.. note::
    This guide covers the :py:class:`hvac.lease_renewer.DatabaseCredentialRenewer`
    helper. It applies to any renewable lease, using the database secrets engine
    (``<mount>/creds/<role>``) as the worked example.

Why the first TTL is not enough
-------------------------------

A ``generate_credentials`` response carries ``lease_id``, ``lease_duration`` and
``renewable``. Scheduling every future renewal from that *first* TTL is wrong
for two reasons:

#. Every ``sys/leases/renew`` response may return a **shorter** TTL than
   requested once the lease approaches its ``max_ttl``. The next timer has to be
   computed from the TTL *just returned*, not from the original one.
#. The lease can stop being renewable at any point: it may have been revoked
   out-of-band (``lease not found``), hit ``max_ttl`` (TTL 0 /
   ``renewable=false``), or the parent Vault token may itself have been revoked
   (HTTP 403). In the first two cases the correct move is to **re-issue** fresh
   credentials; in the last case the process must stop sending requests and
   re-authenticate.

Integration
-----------

.. code:: python

    import os
    import threading
    import hvac
    from hvac.lease_renewer import DatabaseCredentialRenewer

    client = hvac.Client(url="https://vault.example.com", token=os.environ["VAULT_TOKEN"])

    # Called on every issue/re-issue: swap the credentials your DB pool uses.
    def swap_credentials(creds):
        my_db_pool.update_user(creds["username"], creds["password"])

    renewer = DatabaseCredentialRenewer(
        client=client,
        role="app-readonly",
        mount_point="database",
        renew_increment=3600,   # requested; Vault may grant less near max_ttl
        renew_ratio=0.7,        # renew at 70% of the currently granted TTL
        safety_margin=30,       # stop retrying this close to expiry, re-issue
        on_credentials=swap_credentials,
    )

    thread = threading.Thread(target=renewer.run, name="vault-lease-renewer", daemon=True)
    thread.start()

    # Read-only access for request handlers:
    creds = renewer.current_credentials()

    # Graceful shutdown (e.g. SIGTERM handler):
    renewer.stop()
    thread.join(timeout=5)

State machine
-------------

* ``issuing`` / ``reissuing`` -- fetching credentials from
  ``<mount>/creds/<role>``. The old lease is revoked once the new one is held.
* ``renewing`` -- the healthy steady state. After every successful renewal the
  next attempt is scheduled at ``now + granted_ttl * renew_ratio``, so a
  shortened TTL shortens the timer immediately.
* ``stopped`` -- only reachable via :py:meth:`stop` or a parent-token 403.
  No further Vault requests are issued.

Operator log cheat sheet
------------------------

All loggers are named ``hvac.lease_renewer``. The ``event=`` field is stable
and suitable for alerting rules.

.. list-table::
   :header-rows: 1
   :width: 25 15 60

   * - Log line
     - Level
     - Meaning / action
   * - ``event=lease.renewed`` (``lease.renew.success``)
     - INFO
     - Existing lease is still valid; keep using the current DB credentials.
       Note ``granted_ttl`` and ``next_renew_at`` -- the timer follows this TTL.
   * - ``event=lease.renew_retry_scheduled`` (``lease.renew.transient_failure``)
     - WARNING
     - Timeout/5xx/connection error. Existing lease stays in use until its
       expiry; an exponential-backoff retry is scheduled at ``retry_at``.
   * - ``event=lease.reissue_starting`` (``lease.renew.max_ttl_reached``)
     - WARNING
     - Vault returned TTL 0 / non-renewable: ``max_ttl`` reached. New
       credentials are being issued; expect ``event=lease.reissued`` next.
   * - ``event=lease.reissue_starting`` (``lease.renew.lease_not_found``)
     - WARNING
     - Lease was revoked out-of-band. Immediate re-issue, no retry.
   * - ``event=lease.reissue_starting`` (``lease.renew.retry_exhausted``)
     - ERROR
     - Transient failures left no safe retry time before expiry; credentials
       re-issued rather than allowed to expire.
   * - ``event=lease.reissued`` (``lease.issue.success``)
     - INFO
     - New lease active; rotate DB connections to the new username.
   * - ``event=lease.renewer.halted`` (``lease.renew.parent_token_revoked``)
     - ERROR
     - HTTP 403: parent token gone. **The renewer stops issuing all requests.**
       Re-authenticate the client and restart the process.
   * - ``event=lease.renewer.stopped``
     - INFO
     - Clean shutdown after :py:meth:`stop`.

Rule of thumb: while you only see ``lease.renewed`` /
``lease.renew_retry_scheduled``, the current lease remains in use. Any
``lease.reissue_starting`` line means a credential swap is underway.
``lease.renewer.halted`` means traffic has stopped and human action is required.

Local acceptance (no Vault required)
------------------------------------

Both use a fake clock and a scripted in-memory Vault, covering ``max_ttl``
capping, ``lease not found``, parent-token revocation, and timeout-then-success:

.. code:: bash

    # Assertion-based acceptance suite (6 scenarios)
    .venv/bin/python -m pytest tests/acceptance/test_lease_renewer.py -v -s -o addopts=""

    # Narrated demo that prints the exact log lines per scenario
    .venv/bin/python tests/acceptance/run_renewer_demo.py
