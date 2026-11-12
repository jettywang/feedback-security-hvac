Approle
=======

.. contents::

Enabling
--------

:py:meth:`hvac.api.system_backend.Auth.enable_auth_method`

.. code:: python

    import hvac
    client = hvac.Client()

    client.sys.enable_auth_method(
        method_type='approle',
    )

    # Mount approle auth method under a different path:
    client.sys.enable_auth_method(
        method_type='approle',
        path='my-approle',
    )

Authentication
--------------

:py:meth:`hvac.api.auth_methods.AppRole.login`

.. code:: python

    import hvac
    client = hvac.Client()


    client.auth.approle.login(
        role_id='<some_role_id>',
        secret_id='<some_secret_id>',
    )

Create or Update AppRole
------------------------

:py:meth:`hvac.api.auth_methods.AppRole.create_or_update_approle`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.approle.create_or_update_approle(
        role_name='some-role',
        token_policies=['some-policy'],
        token_type='service,
    )

Read Role ID
------------

:py:meth:`hvac.api.auth_methods.AppRole.read_role_id`

.. code:: python

    import hvac
    client = hvac.Client()

    resp = client.auth.approle.read_role_id(
        role_name='some-role',
    )
    print(f'AppRole role ID for some-role: {resp["data"]["role_id"]}')


Generate Secret ID
------------------

:py:meth:`hvac.api.auth_methods.AppRole.generate_secret_id`

.. code:: python

    import hvac
    client = hvac.Client()

    resp = client.auth.approle.generate_secret_id(
        role_name='some-role',
        cidr_list=['127.0.0.1/32'],
    )
    print(f'AppRole secret ID for some-role: {resp["data"]["secret_id"]}')

Per-issuance limits are distinct from the role-level limits
(``secret_id_num_uses``, ``secret_id_ttl``, ``secret_id_bound_cidrs`` set via
:py:meth:`hvac.api.auth_methods.AppRole.create_or_update_approle`). Omitting
``num_uses``/``ttl``/``cidr_list``/``token_bound_cidrs`` leaves the role's
limits in place, while passing them explicitly (including ``0`` or an empty
list) sends them to Vault as an explicit override:

.. code:: python

    import hvac
    client = hvac.Client()

    # Inherit the role's limits: no issuance parameters are sent.
    resp = client.auth.approle.generate_secret_id(
        role_name='some-role',
    )

    # Explicitly request different limits for this one Secret ID:
    # unlimited uses (num_uses=0) and a shorter TTL than the role's.
    resp = client.auth.approle.generate_secret_id(
        role_name='some-role',
        num_uses=0,
        ttl='5m',
        cidr_list=['127.0.0.1/32'],
    )
    print(f'AppRole secret ID for some-role: {resp["data"]["secret_id"]}')

Create Custom Secret ID
-----------------------

:py:meth:`hvac.api.auth_methods.AppRole.create_custom_secret_id`

.. code:: python

    import hvac
    client = hvac.Client()

    resp = client.auth.approle.create_custom_secret_id(
        role_name='some-role',
        secret_id='custom-secret-id',
        num_uses=1,
        ttl='5m',
    )
    print(f'AppRole custom secret ID for some-role: {resp["data"]["secret_id"]}')
