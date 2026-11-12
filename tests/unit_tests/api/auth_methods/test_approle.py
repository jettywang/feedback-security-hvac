from unittest import TestCase

import requests_mock
from parameterized import parameterized

from hvac import exceptions
from hvac.adapters import JSONAdapter
from hvac.api.auth_methods import AppRole
from hvac.constants.approle import DEFAULT_MOUNT_POINT


class TestAppRole(TestCase):
    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT, "default", None),
            ("custom mount point", "approle-test", "default", None),
            (
                "bad token type",
                DEFAULT_MOUNT_POINT,
                "bad_token",
                exceptions.ParamValidationError,
            ),
        ]
    )
    @requests_mock.Mocker()
    def test_create_or_update_approle(
        self, test_label, mount_point, token_type, raises, requests_mocker
    ):
        expected_status_code = 204
        role_name = "testrole"

        mock_url = (
            "http://localhost:8200/v1/auth/{mount_point}/role/{role_name}".format(
                mount_point=mount_point, role_name=role_name
            )
        )
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
        )

        app_role = AppRole(adapter=JSONAdapter())

        if raises is not None:
            with self.assertRaises(raises) as cm:
                app_role.create_or_update_approle(
                    role_name=role_name,
                    token_policies=["default"],
                    token_type=token_type,
                    mount_point=mount_point,
                )
            self.assertIn(member="unsupported token_type", container=str(cm.exception))
        else:
            response = app_role.create_or_update_approle(
                role_name=role_name, token_policies=["default"], mount_point=mount_point
            )

            self.assertEqual(first=expected_status_code, second=response.status_code)

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "approle-test"),
        ]
    )
    @requests_mock.Mocker()
    def test_list_roles(self, test_label, mount_point, requests_mocker):
        expected_status_code = 200
        mock_response = {
            "auth": None,
            "data": {"keys": ["testrole"]},
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "860a11a8-b835-cbab-7fce-de4edc4cf533",
            "warnings": None,
            "wrap_info": None,
        }
        mock_url = "http://localhost:8200/v1/auth/{mount_point}/role".format(
            mount_point=mount_point
        )
        requests_mocker.register_uri(
            method="LIST",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )

        app_role = AppRole(adapter=JSONAdapter())
        response = app_role.list_roles(mount_point=mount_point)

        self.assertEqual(first=mock_response, second=response)

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "approle-test"),
        ]
    )
    @requests_mock.Mocker()
    def test_read_role(self, test_label, mount_point, requests_mocker):
        expected_status_code = 200
        role_name = "testrole"

        mock_response = {
            "auth": None,
            "data": {
                "bind_secret_id": True,
                "local_secret_ids": False,
                "secret_id_bound_cidrs": None,
                "secret_id_num_uses": 0,
                "secret_id_ttl": 0,
                "token_bound_cidrs": None,
                "token_explicit_max_ttl": 0,
                "token_max_ttl": 0,
                "token_no_default_poolicy": False,
                "token_num_uses": 0,
                "token_period": 14400,
                "token_policies": None,
                "token_ttl": 0,
                "token_type": "default",
            },
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "860a11a8-b835-cbab-7fce-de4edc4cf533",
            "warnings": None,
            "wrap_info": None,
        }
        mock_url = (
            "http://localhost:8200/v1/auth/{mount_point}/role/{role_name}".format(
                mount_point=mount_point, role_name=role_name
            )
        )
        requests_mocker.register_uri(
            method="GET",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )

        app_role = AppRole(adapter=JSONAdapter())
        response = app_role.read_role(role_name="testrole", mount_point=mount_point)

        self.assertEqual(first=mock_response, second=response)

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "approle-test"),
        ]
    )
    @requests_mock.Mocker()
    def test_delete_role(self, test_label, mount_point, requests_mocker):
        expected_status_code = 204
        role_name = "testrole"

        mock_url = (
            "http://localhost:8200/v1/auth/{mount_point}/role/{role_name}".format(
                mount_point=mount_point, role_name=role_name
            )
        )
        requests_mocker.register_uri(
            method="DELETE",
            url=mock_url,
            status_code=expected_status_code,
        )

        app_role = AppRole(adapter=JSONAdapter())
        response = app_role.delete_role(role_name=role_name, mount_point=mount_point)

        self.assertEqual(first=expected_status_code, second=response.status_code)

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "approle-test"),
        ]
    )
    @requests_mock.Mocker()
    def test_read_role_id(self, test_label, mount_point, requests_mocker):
        expected_status_code = 200
        role_name = "testrole"

        mock_response = {
            "auth": None,
            "data": {"role_id": "e5a7b66e-5d08-da9c-7075-71984634b882"},
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "860a11a8-b835-cbab-7fce-de4edc4cf533",
            "warnings": None,
            "wrap_info": None,
        }
        mock_url = "http://localhost:8200/v1/auth/{mount_point}/role/{role_name}/role-id".format(
            mount_point=mount_point, role_name=role_name
        )
        requests_mocker.register_uri(
            method="GET",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )

        app_role = AppRole(adapter=JSONAdapter())
        response = app_role.read_role_id(role_name=role_name, mount_point=mount_point)

        self.assertEqual(first=mock_response, second=response)

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "approle-test"),
        ]
    )
    @requests_mock.Mocker()
    def test_update_role_id(self, test_label, mount_point, requests_mocker):
        expected_status_code = 200
        role_name = "testrole"
        role_id = "test_role_id"

        mock_response = {
            "auth": None,
            "data": {"role_id": role_id},
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "860a11a8-b835-cbab-7fce-de4edc4cf533",
            "warnings": None,
            "wrap_info": None,
        }
        mock_url = "http://localhost:8200/v1/auth/{mount_point}/role/{role_name}/role-id".format(
            mount_point=mount_point, role_name=role_name
        )
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )

        app_role = AppRole(adapter=JSONAdapter())
        response = app_role.update_role_id(
            role_name=role_name, role_id=role_id, mount_point=mount_point
        )

        self.assertEqual(first=mock_response, second=response)

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT, None, None, None),
            (
                "metadata as dict",
                DEFAULT_MOUNT_POINT,
                None,
                {"a": "val1", "b": "two"},
                300,
            ),
            (
                "invalid metadata",
                DEFAULT_MOUNT_POINT,
                exceptions.ParamValidationError,
                "bad metadata",
                None,
            ),
            ("custom mount point", "approle-test", None, None, "5m"),
        ]
    )
    @requests_mock.Mocker()
    def test_generate_secret_id(
        self, test_label, mount_point, raises, metadata, wrap_ttl, requests_mocker
    ):
        expected_status_code = 200
        role_name = "testrole"

        mock_response = {
            "auth": None,
            "data": {
                "secret_id": "841771dc-11c9-bbc7-bcac-6a3945a69cd9",
                "secret_id_accessor": "84896a0c-1347-aa90-a4f6-aca8b7558780",
            },
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "860a11a8-b835-cbab-7fce-de4edc4cf533",
            "warnings": None,
            "wrap_info": None,
        }

        mock_url = "http://localhost:8200/v1/auth/{mount_point}/role/{role_name}/secret-id".format(
            mount_point=mount_point, role_name=role_name
        )
        adapter = requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )

        app_role = AppRole(adapter=JSONAdapter())

        if raises is not None:
            with self.assertRaises(raises) as cm:
                app_role.generate_secret_id(
                    role_name=role_name,
                    metadata=metadata,
                    mount_point=mount_point,
                    wrap_ttl=wrap_ttl,
                )
            self.assertIn(
                member="unsupported metadata argument", container=str(cm.exception)
            )
            assert adapter.call_count == 0

        else:
            response = app_role.generate_secret_id(
                role_name=role_name,
                cidr_list=["127.0.0.1/32"],
                mount_point=mount_point,
                metadata=metadata,
                wrap_ttl=wrap_ttl,
            )

            self.assertEqual(first=mock_response, second=response)
            assert adapter.call_count == 1
            last_request = adapter.last_request
            assert ("metadata" in last_request.json()) == (metadata is not None)

            if wrap_ttl is None:
                assert "X-Vault-Wrap-TTL" not in last_request.headers
            else:
                assert "X-Vault-Wrap-TTL" in last_request.headers
                assert last_request.headers["X-Vault-Wrap-TTL"] == str(wrap_ttl)

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT, None, None, None),
            (
                "metadata as dict",
                DEFAULT_MOUNT_POINT,
                None,
                {"a": "val1", "b": "two"},
                300,
            ),
            (
                "invalid metadata",
                DEFAULT_MOUNT_POINT,
                exceptions.ParamValidationError,
                "bad metadata",
                None,
            ),
            ("custom mount point", "approle-test", None, None, "5m"),
        ]
    )
    @requests_mock.Mocker()
    def test_create_custom_secret_id(
        self, test_label, mount_point, raises, metadata, wrap_ttl, requests_mocker
    ):
        expected_status_code = 200
        role_name = "testrole"
        secret_id = "custom_secret"

        mock_response = {
            "auth": None,
            "data": {
                "secret_id": secret_id,
                "secret_id_accessor": "84896a0c-1347-aa90-a4f6-aca8b7558780",
            },
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "860a11a8-b835-cbab-7fce-de4edc4cf533",
            "warnings": None,
            "wrap_info": None,
        }
        mock_url = "http://localhost:8200/v1/auth/{mount_point}/role/{role_name}/custom-secret-id".format(
            mount_point=mount_point, role_name=role_name
        )
        adapter = requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )

        app_role = AppRole(adapter=JSONAdapter())

        if raises is not None:
            with self.assertRaises(raises) as cm:
                app_role.create_custom_secret_id(
                    role_name=role_name,
                    secret_id=secret_id,
                    cidr_list=["127.0.0.1/32"],
                    metadata=metadata,
                    mount_point=mount_point,
                    wrap_ttl=wrap_ttl,
                )
            self.assertIn(
                member="unsupported metadata argument", container=str(cm.exception)
            )
            assert adapter.call_count == 0
        else:
            response = app_role.create_custom_secret_id(
                role_name=role_name,
                secret_id=secret_id,
                cidr_list=["127.0.0.1/32"],
                mount_point=mount_point,
                metadata=metadata,
                wrap_ttl=wrap_ttl,
            )

            self.assertEqual(first=mock_response, second=response)
            assert adapter.call_count == 1
            last_request = adapter.last_request
            assert ("metadata" in last_request.json()) == (metadata is not None)

            if wrap_ttl is None:
                assert "X-Vault-Wrap-TTL" not in last_request.headers
            else:
                assert "X-Vault-Wrap-TTL" in last_request.headers
                assert last_request.headers["X-Vault-Wrap-TTL"] == str(wrap_ttl)

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "approle-test"),
        ]
    )
    @requests_mock.Mocker()
    def test_read_secret_id(self, test_label, mount_point, requests_mocker):
        expected_status_code = 200
        role_name = "testrole"
        secret_id = "custom_secret"

        mock_response = {
            "auth": None,
            "data": {
                "secret_id": secret_id,
                "secret_id_accessor": "84896a0c-1347-aa90-a4f6-aca8b7558780",
            },
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "860a11a8-b835-cbab-7fce-de4edc4cf533",
            "warnings": None,
            "wrap_info": None,
        }
        mock_url = "http://localhost:8200/v1/auth/{mount_point}/role/{role_name}/secret-id/lookup".format(
            mount_point=mount_point, role_name=role_name
        )
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )

        app_role = AppRole(adapter=JSONAdapter())
        response = app_role.read_secret_id(
            role_name=role_name, secret_id=secret_id, mount_point=mount_point
        )

        self.assertEqual(first=mock_response, second=response)

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "approle-test"),
        ]
    )
    @requests_mock.Mocker()
    def test_destroy_secret_id(self, test_label, mount_point, requests_mocker):
        expected_status_code = 204
        role_name = "testrole"
        secret_id = "custom_secret"

        mock_url = "http://localhost:8200/v1/auth/{mount_point}/role/{role_name}/secret-id/destroy".format(
            mount_point=mount_point, role_name=role_name
        )
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
        )

        app_role = AppRole(adapter=JSONAdapter())
        response = app_role.destroy_secret_id(
            role_name=role_name, secret_id=secret_id, mount_point=mount_point
        )

        self.assertEqual(first=expected_status_code, second=response.status_code)

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "approle-test"),
        ]
    )
    @requests_mock.Mocker()
    def test_list_secret_id_accessors(self, test_label, mount_point, requests_mocker):
        expected_status_code = 200
        role_name = "testrole"

        mock_response = {
            "auth": None,
            "data": {
                "keys": [
                    "ce102d2a-8253-c437-bf9a-aceed4241491",
                    "a1c8dee4-b869-e68d-3520-2040c1a0849a",
                    "be83b7e2-044c-7244-07e1-47560ca1c787",
                    "84896a0c-1347-aa90-a4f6-aca8b7558780",
                    "239b1328-6523-15e7-403a-a48038cdc45a",
                ]
            },
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "860a11a8-b835-cbab-7fce-de4edc4cf533",
            "warnings": None,
            "wrap_info": None,
        }
        mock_url = "http://localhost:8200/v1/auth/{mount_point}/role/{role_name}/secret-id".format(
            mount_point=mount_point, role_name=role_name
        )
        requests_mocker.register_uri(
            method="LIST",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )

        app_role = AppRole(adapter=JSONAdapter())
        response = app_role.list_secret_id_accessors(
            role_name=role_name, mount_point=mount_point
        )

        self.assertEqual(first=mock_response, second=response)

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "approle-test"),
        ]
    )
    @requests_mock.Mocker()
    def test_read_secret_id_accessor(self, test_label, mount_point, requests_mocker):
        expected_status_code = 200
        role_name = "testrole"
        secret_id = "custom_secret"
        secret_id_accessor = "84896a0c-1347-aa90-a4f6-aca8b7558780"

        mock_response = {
            "auth": None,
            "data": {
                "secret_id": secret_id,
                "secret_id_accessor": "84896a0c-1347-aa90-a4f6-aca8b7558780",
            },
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "860a11a8-b835-cbab-7fce-de4edc4cf533",
            "warnings": None,
            "wrap_info": None,
        }
        mock_url = "http://localhost:8200/v1/auth/{mount_point}/role/{role_name}/secret-id-accessor/lookup".format(
            mount_point=mount_point, role_name=role_name
        )
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )

        app_role = AppRole(adapter=JSONAdapter())
        response = app_role.read_secret_id_accessor(
            role_name=role_name,
            secret_id_accessor=secret_id_accessor,
            mount_point=mount_point,
        )

        self.assertEqual(first=mock_response, second=response)

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "approle-test"),
        ]
    )
    @requests_mock.Mocker()
    def test_destroy_secret_id_accessor(self, test_label, mount_point, requests_mocker):
        expected_status_code = 204
        role_name = "testrole"
        secret_id_accessor = "84896a0c-1347-aa90-a4f6-aca8b7558780"

        mock_url = "http://localhost:8200/v1/auth/{mount_point}/role/{role_name}/secret-id-accessor/destroy".format(
            mount_point=mount_point, role_name=role_name
        )
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
        )

        app_role = AppRole(adapter=JSONAdapter())
        response = app_role.destroy_secret_id_accessor(
            role_name=role_name,
            secret_id_accessor=secret_id_accessor,
            mount_point=mount_point,
        )

        self.assertEqual(first=expected_status_code, second=response.status_code)

    @parameterized.expand(
        [
            ("default mount point", DEFAULT_MOUNT_POINT),
            ("custom mount point", "approle-test"),
        ]
    )
    @requests_mock.Mocker()
    def test_login(self, test_label, mount_point, requests_mocker):
        expected_status_code = 200
        role_id = "test_role_id"
        secret_id = "custom_secret"

        mock_response = {
            "data": None,
            "auth": {
                "renewable": True,
                "lease_duration": 1200,
                "metadata": None,
                "token_policies": ["default"],
                "accessor": "fd6c9a00-d2dc-3b11-0be5-af7ae0e1d374",
                "client_token": "5b1a0318-679c-9c45-e5c6-d1b9a9035d49",
            },
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "860a11a8-b835-cbab-7fce-de4edc4cf533",
            "warnings": None,
            "wrap_info": None,
        }
        mock_url = "http://localhost:8200/v1/auth/{mount_point}/login".format(
            mount_point=mount_point,
        )
        requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response,
        )

        app_role = AppRole(adapter=JSONAdapter())
        response = app_role.login(
            role_id=role_id, secret_id=secret_id, mount_point=mount_point
        )

        self.assertEqual(first=mock_response, second=response)


class TestAppRoleSecretIDIssuanceParams(TestCase):
    """Regression tests for per-issuance Secret ID parameters.

    Role-level limits (``secret_id_num_uses``, ``secret_id_ttl``,
    ``secret_id_bound_cidrs``) are configured on the role itself, while the
    issuance endpoints accept their own ``num_uses``, ``ttl``, ``cidr_list``
    and ``token_bound_cidrs`` fields. hvac must omit parameters that were not
    passed so Vault keeps the role's limits, while still forwarding explicit
    zero values and empty lists so the server can tell "inherit the role
    limits" apart from "explicitly request different limits".
    """

    role_name = "testrole"
    custom_secret_id = "custom_secret"

    def _issue_secret_id(
        self, requests_mocker, endpoint, status_code=200, response=None, **kwargs
    ):
        mock_url = (
            "http://localhost:8200/v1/auth/{mount_point}/role/{role_name}/{endpoint}".format(
                mount_point=DEFAULT_MOUNT_POINT,
                role_name=self.role_name,
                endpoint=endpoint,
            )
        )
        adapter = requests_mocker.register_uri(
            method="POST",
            url=mock_url,
            status_code=status_code,
            json=response,
        )

        app_role = AppRole(adapter=JSONAdapter())
        if endpoint == "secret-id":
            result = app_role.generate_secret_id(role_name=self.role_name, **kwargs)
        else:
            result = app_role.create_custom_secret_id(
                role_name=self.role_name,
                secret_id=self.custom_secret_id,
                **kwargs,
            )
        return adapter, result

    @staticmethod
    def _expected_body(endpoint, **fields):
        body = dict(fields)
        if endpoint == "custom-secret-id":
            body["secret_id"] = TestAppRoleSecretIDIssuanceParams.custom_secret_id
        return body

    @parameterized.expand(
        [
            ("generate", "secret-id"),
            ("custom", "custom-secret-id"),
        ]
    )
    @requests_mock.Mocker()
    def test_issuance_params_not_set_inherit_role_limits(
        self, test_label, endpoint, requests_mocker
    ):
        mock_response = {
            "auth": None,
            "data": {
                "secret_id": "841771dc-11c9-bbc7-bcac-6a3945a69cd9",
                "secret_id_accessor": "84896a0c-1347-aa90-a4f6-aca8b7558780",
            },
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "860a11a8-b835-cbab-7fce-de4edc4cf533",
            "warnings": None,
            "wrap_info": None,
        }
        adapter, response = self._issue_secret_id(
            requests_mocker, endpoint, response=mock_response
        )

        self.assertEqual(first=mock_response, second=response)
        self.assertEqual(first=1, second=adapter.call_count)
        self.assertEqual(
            first=self._expected_body(endpoint),
            second=adapter.last_request.json(),
        )

    @parameterized.expand(
        [
            ("generate", "secret-id"),
            ("custom", "custom-secret-id"),
        ]
    )
    @requests_mock.Mocker()
    def test_issuance_params_explicit_zero_forwarded(
        self, test_label, endpoint, requests_mocker
    ):
        adapter, _ = self._issue_secret_id(
            requests_mocker, endpoint, num_uses=0, ttl=0
        )

        self.assertEqual(first=1, second=adapter.call_count)
        self.assertEqual(
            first=self._expected_body(endpoint, num_uses=0, ttl=0),
            second=adapter.last_request.json(),
        )

    @parameterized.expand(
        [
            ("generate", "secret-id"),
            ("custom", "custom-secret-id"),
        ]
    )
    @requests_mock.Mocker()
    def test_issuance_params_explicit_values_forwarded(
        self, test_label, endpoint, requests_mocker
    ):
        adapter, _ = self._issue_secret_id(
            requests_mocker, endpoint, num_uses=3, ttl="10m"
        )

        self.assertEqual(first=1, second=adapter.call_count)
        self.assertEqual(
            first=self._expected_body(endpoint, num_uses=3, ttl="10m"),
            second=adapter.last_request.json(),
        )

    @parameterized.expand(
        [
            ("generate", "secret-id"),
            ("custom", "custom-secret-id"),
        ]
    )
    @requests_mock.Mocker()
    def test_issuance_params_empty_lists_forwarded(
        self, test_label, endpoint, requests_mocker
    ):
        adapter, _ = self._issue_secret_id(
            requests_mocker, endpoint, cidr_list=[], token_bound_cidrs=[]
        )

        self.assertEqual(first=1, second=adapter.call_count)
        self.assertEqual(
            first=self._expected_body(endpoint, cidr_list="", token_bound_cidrs=""),
            second=adapter.last_request.json(),
        )

    @parameterized.expand(
        [
            ("generate", "secret-id"),
            ("custom", "custom-secret-id"),
        ]
    )
    @requests_mock.Mocker()
    def test_issuance_params_cidr_lists_forwarded(
        self, test_label, endpoint, requests_mocker
    ):
        adapter, _ = self._issue_secret_id(
            requests_mocker,
            endpoint,
            cidr_list=["127.0.0.1/32", "10.0.0.0/8"],
            token_bound_cidrs=["192.168.0.0/16"],
        )

        self.assertEqual(first=1, second=adapter.call_count)
        self.assertEqual(
            first=self._expected_body(
                endpoint,
                cidr_list="127.0.0.1/32,10.0.0.0/8",
                token_bound_cidrs="192.168.0.0/16",
            ),
            second=adapter.last_request.json(),
        )

    @parameterized.expand(
        [
            ("generate", "secret-id"),
            ("custom", "custom-secret-id"),
        ]
    )
    @requests_mock.Mocker()
    def test_issuance_params_constraint_conflict(
        self, test_label, endpoint, requests_mocker
    ):
        conflict = {
            "errors": [
                "requested ttl exceeds the role's secret_id_ttl",
            ]
        }
        with self.assertRaises(exceptions.InvalidRequest) as cm:
            self._issue_secret_id(
                requests_mocker,
                endpoint,
                status_code=400,
                response=conflict,
                num_uses=0,
                ttl=0,
            )

        self.assertIn(
            member="requested ttl exceeds the role's secret_id_ttl",
            container=str(cm.exception),
        )

    @parameterized.expand(
        [
            ("generate", "secret-id"),
            ("custom", "custom-secret-id"),
        ]
    )
    @requests_mock.Mocker()
    def test_issuance_params_normal_credentials(
        self, test_label, endpoint, requests_mocker
    ):
        mock_response = {
            "auth": None,
            "data": {
                "secret_id": "841771dc-11c9-bbc7-bcac-6a3945a69cd9",
                "secret_id_accessor": "84896a0c-1347-aa90-a4f6-aca8b7558780",
                "secret_id_num_uses": 0,
                "secret_id_ttl": 600,
            },
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "860a11a8-b835-cbab-7fce-de4edc4cf533",
            "warnings": None,
            "wrap_info": None,
        }
        adapter, response = self._issue_secret_id(
            requests_mocker,
            endpoint,
            response=mock_response,
            num_uses=0,
            ttl=600,
        )

        self.assertEqual(first=mock_response, second=response)
        self.assertEqual(first=1, second=adapter.call_count)
        self.assertEqual(
            first=self._expected_body(endpoint, num_uses=0, ttl=600),
            second=adapter.last_request.json(),
        )
