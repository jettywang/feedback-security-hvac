Request-scoped namespace and token
==================================

.. contents::
   :local:
   :depth: 1

A single service often talks to more than one Vault namespace, and each
namespace may require its own token. The ``Client`` (and its underlying
adapter) is normally shared across threads, so mutating
``client.adapter.namespace`` or ``client.adapter.token`` around an individual
call is **not** safe: another concurrent request can observe the temporary
value and send its request with the wrong identity.

Use one of the approaches below instead. Both keep the shared adapter's
configuration untouched, so concurrent requests always carry the namespace and
token that belong to their own call.

The unsafe pattern
------------------

.. code:: python

    # Do NOT do this: the attributes live on a shared, long-lived adapter and
    # another in-flight request can read them while they are temporarily changed.
    client.adapter.namespace = "team-b"
    try:
        client.secrets.kv.v2.read_secret_version(path="app/config")
    finally:
        client.adapter.namespace = "team-a"

Per-request overrides
---------------------

Every adapter request accepts ``namespace`` and ``token`` keyword arguments.
They affect only that single request; the adapter's ``namespace`` and ``token``
attributes are never modified.

.. code:: python

    import hvac

    client = hvac.Client(
        url="https://vault.example:8200",
        namespace="team-a",
        token="team-a-token",
    )

    # Uses the adapter defaults: X-Vault-Namespace: team-a, token team-a-token.
    client.secrets.kv.v2.read_secret_version(path="app/config")

    # One-off call into a second namespace with its own token. Nothing on the
    # shared client changes, so this is safe to run alongside other requests.
    client.adapter.request(
        "get",
        "/v1/secret/data/app/config",
        namespace="team-b",
        token="team-b-token",
    )

The arguments follow these rules:

* Not supplied (the default): the adapter's configured ``namespace`` / ``token``
  is used.
* A string: overrides the configured value for this request only.
* Explicitly ``None``: suppresses the ``X-Vault-Namespace`` / ``X-Vault-Token``
  header for this request, even when the adapter has a value configured.

Cloning the adapter
-------------------

When a whole component is dedicated to one namespace, give it its own adapter
with :py:meth:`hvac.adapters.Adapter.clone`. The clone inherits every setting,
including the shared ``requests`` session (and therefore its connection pool),
but carries its own identity.

.. code:: python

    team_a_client = hvac.Client(
        url="https://vault.example:8200",
        namespace="team-a",
        token="team-a-token",
    )

    team_b_adapter = team_a_client.adapter.clone(
        namespace="team-b",
        token="team-b-token",
    )

    # Both adapters can be used concurrently without interfering.
    team_a_client.secrets.kv.v2.read_secret_version(path="app/config")
    team_b_adapter.get("/v1/secret/data/app/config")

A clone created without arguments is an equivalent adapter that shares the
original session.

Redirects
---------

Vault answers are occasionally returned with an HTTP redirect. hvac builds the
``X-Vault-Namespace`` and ``X-Vault-Token`` headers itself and relies on
``requests`` to follow redirects, which leads to different behavior than with
the standard ``Authorization`` header:

* **Same target** (same host, scheme and port): every authentication header is
  re-sent on the redirected request — ``X-Vault-Token``,
  ``X-Vault-Namespace`` and any caller-supplied ``Authorization`` header.
* **Different target** (a different host, or a changed scheme/port):
  ``requests`` strips only the standard ``Authorization`` header. The
  ``X-Vault-Token`` and ``X-Vault-Namespace`` headers are **still sent** to the
  new host, because ``requests`` does not treat them as authentication headers.

Because a cross-host redirect can therefore leak a Vault token or namespace
path to a foreign host, only follow redirects to targets you trust. If a
proxy or load balancer may redirect to a different host, set
``allow_redirects=False`` on the client (or on a cloned adapter) and handle the
``3xx`` response explicitly instead.
