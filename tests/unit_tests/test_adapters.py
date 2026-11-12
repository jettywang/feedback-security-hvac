#!/usr/bin/env python
import threading

import pytest
import logging
from unittest import TestCase
from unittest import mock

import requests_mock
from requests_mock.response import create_response
from parameterized import parameterized, param
from hvac.constants.client import DEFAULT_URL
from hvac import exceptions
from hvac import adapters
from tests import utils
from hvac import Client
import requests


class TestAdapters:
    CONSTRUCTOR_ARGS = (
        "base_uri",
        "token",
        "cert",
        "verify",
        "timeout",
        "proxies",
        "allow_redirects",
        "session",
        "namespace",
        "ignore_exceptions",
        "strict_http",
        "request_header",
    )

    INTERNAL_KWARGS = (
        "cert",
        "verify",
        "timeout",
        "proxies",
    )

    @pytest.mark.parametrize(
        "conargs",
        [
            {arg: arg.capitalize() for arg in CONSTRUCTOR_ARGS},
            {arg: arg.upper() for arg in CONSTRUCTOR_ARGS},
        ],
    )
    def test_from_adapter(self, conargs):
        # set session to None so that the adapter will create its own internally
        conargs["session"] = None
        expected = conargs.copy()
        for internal_kwarg in self.INTERNAL_KWARGS:
            expected.setdefault("_kwargs", {})[internal_kwarg] = expected.pop(
                internal_kwarg
            )

        # let's start with a JSONAdapter, and make a RawAdapter out of it
        json_adapter = adapters.JSONAdapter(**conargs)

        # reset the expected session to to be the one created by the JSONAdapter
        expected["session"] = json_adapter.session

        raw_adapter = adapters.RawAdapter.from_adapter(json_adapter)

        for property, value in expected.items():
            assert getattr(raw_adapter, property) == value


class TestRequest(TestCase):
    """Unit tests providing coverage for requests-related methods in the hvac Client class."""

    @parameterized.expand(
        [
            param(
                "standard Vault address",
                url="https://localhost:8200",
            ),
            param(
                "Vault address with route",
                url="https://example.com/vault",
            ),
            param(
                "regression test for hvac issue #51",
                url="https://localhost:8200",
                path="keyring/http://some.url/sub/entry",
            ),
            param(
                "redirect with location header for issue #343",
                url="https://localhost:8200",
                path="secret/some-secret",
                redirect_url="https://some-other-place.com/secret/some-secret",
            ),
        ]
    )
    def test_get(self, label, url, path="v1/sys/health", redirect_url=None):
        path = path.replace("//", "/")
        expected_status_code = 200
        mock_url = f"{url}/{path}"
        expected_request_urls = [mock_url]
        adapter = adapters.RawAdapter(base_uri=url)
        response_headers = {}
        response_status_code = 200
        if redirect_url is not None:
            response_headers["Location"] = redirect_url
            response_status_code = 301
        with requests_mock.mock() as requests_mocker:
            logging.debug('Registering "mock_url": %s' % mock_url)
            requests_mocker.register_uri(
                method="GET",
                url=mock_url,
                headers=response_headers,
                status_code=response_status_code,
            )
            if redirect_url is not None:
                expected_request_urls.append(redirect_url)
                logging.debug('Registering "redirect_url": %s' % redirect_url)
                requests_mocker.register_uri(
                    method="GET",
                    url=redirect_url,
                )

            response = adapter.get(
                url=path,
            )

        # Assert all our expected uri(s) were requested
        for request_num, expected_request_url in enumerate(expected_request_urls):
            self.assertEqual(
                first=expected_request_url,
                second=requests_mocker.request_history[request_num].url,
            )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )

    @parameterized.expand(
        [
            ("kv secret lookup", "v1/secret/some-secret"),
        ]
    )
    @requests_mock.Mocker()
    def test_list(self, test_label, test_path, requests_mocker):
        mock_response = {
            "auth": None,
            "data": {"keys": ["things1", "things2"]},
            "lease_duration": 0,
            "lease_id": "",
            "renewable": False,
            "request_id": "ba933afe-84d4-410f-161b-592a5c016009",
            "warnings": None,
            "wrap_info": None,
        }
        expected_status_code = 200
        mock_url = f"{DEFAULT_URL}/{test_path}"
        requests_mocker.register_uri(method="LIST", url=mock_url, json=mock_response)
        adapter = adapters.RawAdapter()
        response = adapter.list(
            url=test_path,
        )
        self.assertEqual(
            first=expected_status_code,
            second=response.status_code,
        )
        self.assertEqual(first=mock_response, second=response.json())


@pytest.fixture
def raw_adapter():
    return mock.Mock(wraps=adapters.RawAdapter())


class TestRawAdapter:
    @pytest.mark.parametrize("headers", [{}, {"Content-Type": "application/json"}])
    @pytest.mark.parametrize("json_get", [None, Exception])
    @pytest.mark.parametrize("text_get", [None, Exception])
    @pytest.mark.parametrize(
        "bytes", [None, b"", b"a", b"{}", b'{"errors": ["err"]}', b"\x80\x81", b"\0"]
    )
    @pytest.mark.parametrize("code", [404, 500])
    def test_raise_for_error(
        self, raw_adapter, headers, bytes, code, json_get, text_get
    ):
        url = "throwaway"
        method = "GET"

        resp = create_response(
            mock.Mock(url=url), status_code=code, content=bytes, headers=headers
        )

        resp.json = mock.Mock(wraps=resp.json, side_effect=json_get)

        mock_text = mock.PropertyMock(wraps=resp.text, side_effect=text_get)
        with mock.patch("requests.Response.text", new=mock_text):
            if text_get is not None:
                with pytest.raises(Exception):
                    resp.text

            text = errors = json = None

            if headers:
                try:
                    json = resp.json()
                except Exception:
                    pass
                else:
                    errors = json.get("errors")

            try:
                text = resp.text
            except Exception:
                pass

            from hvac.utils import raise_for_error

            with mock.patch(
                "hvac.utils.raise_for_error", mock.Mock(wraps=raise_for_error)
            ) as r:
                with pytest.raises(exceptions.VaultError) as e:
                    raw_adapter._raise_for_error(method, url, resp)

                e_msg = None if errors else text
                expected = mock.call(
                    method, url, code, e_msg, errors=errors, text=text, json=json
                )

                assert r.call_count == 1
                r.assert_has_calls([expected])
                assert e.value.text == text
                assert e.value.json == json
                assert e.value.errors == errors


class TestAdapterVerify(TestCase):
    @parameterized.expand(
        [
            param("Testing default", verify=Client().session.verify, use_session=False),
            param(
                "Testing default session",
                verify=Client().session.verify,
                use_session=True,
            ),
            param("Testing verify true", verify=True, use_session=False),
            param("Testing verify true session", verify=True, use_session=True),
            param("Testing verify false", verify=False, use_session=False),
            param("Testing verify false session", verify=False, use_session=True),
            param(
                "use certificate for verify #991",
                verify=utils.get_config_file_path("client-cert.pem"),
                use_session=False,
            ),
            param(
                "use certificate from session #991",
                verify=utils.get_config_file_path("client-cert.pem"),
                use_session=True,
            ),
        ]
    )
    def test_session_verify_stickiness(self, label, verify, use_session):
        if use_session:
            s = requests.Session()
            s.verify = verify
            c = Client(session=s)
        elif verify is not None:
            c = Client(verify=verify)
        else:
            c = Client()
        assert c._adapter.session.verify == verify
        assert c._adapter.session

    @parameterized.expand(
        [
            param("Testing default", cert=None, use_session=False),
            param("Testing default with session", cert=None, use_session=False),
            param(
                "use certificate for #991",
                cert=utils.get_config_file_path("client-cert.pem"),
                use_session=False,
            ),
            param(
                "use certificate from session #991",
                cert=utils.get_config_file_path("client-cert.pem"),
                use_session=True,
            ),
        ]
    )
    def test_session_certificate_stickiness(self, label, cert, use_session):
        if use_session:
            s = requests.Session()
            s.cert = cert
            c = Client(session=s)
        elif cert is not None:
            c = Client(cert=cert)
        else:
            c = Client()
        assert c._adapter.session.cert == cert
        assert c._adapter.session

    @parameterized.expand(
        [
            param("Testing default", proxies=None, use_session=False),
            param(
                "Testing default session",
                proxies=None,
                use_session=True,
            ),
            param("Testing Proxy", proxies="localhost:8080", use_session=False),
            param("Testing Proxy session", proxies="localhost:8080", use_session=True),
        ]
    )
    def test_session_proxies_stickiness(self, label, proxies, use_session):
        if use_session:
            s = requests.Session()
            s.proxies = proxies
            c = Client(session=s)
        elif proxies is not None:
            c = Client(proxies=proxies)
        else:
            c = Client()
        assert c._adapter.session.proxies == proxies
        assert c._adapter.session


class FakeSession:
    """Minimal stand-in for ``requests.Session`` recording every request.

    It performs no networking and returns a plain 200 ``requests.Response``,
    which lets tests assert on the exact URL and headers the adapter produced
    without standing up a Vault server.
    """

    def __init__(self):
        self.calls = []
        self.verify = None
        self.cert = None
        self.proxies = None

    def request(self, method, url, headers=None, allow_redirects=True, **kwargs):
        recorded = mock.Mock()
        recorded.method = method
        recorded.url = url
        recorded.headers = dict(headers or {})
        recorded.allow_redirects = allow_redirects
        recorded.kwargs = kwargs
        self.calls.append(recorded)

        response = requests.Response()
        response.status_code = 200
        response._content = b'{"data": {}}'
        response.headers["Content-Type"] = "application/json"
        response.request = recorded
        return response

    def close(self):
        pass


class TestRequestScopedIdentity:
    """Coverage for passing namespace/token per request instead of mutating a shared adapter."""

    BASE_URI = "https://vault.example:8200"
    DEFAULT_NAMESPACE = "team-a"
    DEFAULT_TOKEN = "default-token"

    def _adapter(self, **kwargs):
        session = FakeSession()
        kwargs.setdefault("base_uri", self.BASE_URI)
        kwargs.setdefault("namespace", self.DEFAULT_NAMESPACE)
        kwargs.setdefault("token", self.DEFAULT_TOKEN)
        return adapters.RawAdapter(session=session, **kwargs), session

    def test_unset_arguments_use_adapter_defaults(self):
        adapter, session = self._adapter()

        adapter.get("v1/secret/data/default")

        (sent,) = session.calls
        assert sent.headers["X-Vault-Namespace"] == self.DEFAULT_NAMESPACE
        assert sent.headers["X-Vault-Token"] == self.DEFAULT_TOKEN
        assert sent.headers["X-Vault-Request"] == "true"
        assert sent.url == f"{self.BASE_URI}/v1/secret/data/default"
        # Nothing on the shared adapter changed.
        assert adapter.namespace == self.DEFAULT_NAMESPACE
        assert adapter.token == self.DEFAULT_TOKEN

    @pytest.mark.parametrize(
        "override_kwargs",
        [
            {"namespace": "team-b"},
            {"token": "other-token"},
            {"namespace": "team-b", "token": "other-token"},
        ],
    )
    def test_explicit_overrides_apply_to_one_request_only(self, override_kwargs):
        adapter, session = self._adapter()

        adapter.get("v1/secret/data/scoped", **override_kwargs)
        # A follow-up call without overrides must fall back to the defaults.
        adapter.get("v1/secret/data/default")

        scoped_call, default_call = session.calls
        assert scoped_call.headers.get("X-Vault-Namespace") == override_kwargs.get(
            "namespace", self.DEFAULT_NAMESPACE
        )
        assert scoped_call.headers.get("X-Vault-Token") == override_kwargs.get(
            "token", self.DEFAULT_TOKEN
        )
        assert default_call.headers["X-Vault-Namespace"] == self.DEFAULT_NAMESPACE
        assert default_call.headers["X-Vault-Token"] == self.DEFAULT_TOKEN
        # The adapter's own attributes are never mutated by an override.
        assert adapter.namespace == self.DEFAULT_NAMESPACE
        assert adapter.token == self.DEFAULT_TOKEN

    @pytest.mark.parametrize(
        "adapter_kwargs,request_kwargs,absent_headers",
        [
            # Explicit None suppresses a header the adapter would otherwise send.
            (
                {"namespace": "team-a", "token": "tok-a"},
                {"namespace": None},
                ["X-Vault-Namespace"],
            ),
            (
                {"namespace": "team-a", "token": "tok-a"},
                {"token": None},
                ["X-Vault-Token"],
            ),
            (
                {"namespace": "team-a", "token": "tok-a"},
                {"namespace": None, "token": None},
                ["X-Vault-Namespace", "X-Vault-Token"],
            ),
            # An adapter configured without identity sends no identity headers by default.
            ({"namespace": None, "token": None}, {}, ["X-Vault-Namespace", "X-Vault-Token"]),
        ],
    )
    def test_none_disables_header_for_single_request(
        self, adapter_kwargs, request_kwargs, absent_headers
    ):
        session = FakeSession()
        adapter = adapters.RawAdapter(base_uri=self.BASE_URI, session=session, **adapter_kwargs)

        adapter.get("v1/secret/data/anon", **request_kwargs)

        (sent,) = session.calls
        for header in absent_headers:
            assert header not in sent.headers

    def test_raises_exception_on_error_response(self):
        adapter, session = self._adapter()

        def forbidden(method, url, headers=None, allow_redirects=True, **kwargs):
            response = requests.Response()
            response.status_code = 403
            response._content = b'{"errors": ["permission denied"]}'
            response.headers["Content-Type"] = "application/json"
            return response

        session.request = forbidden
        with pytest.raises(exceptions.Forbidden):
            adapter.get(
                "v1/secret/data/missing",
                namespace="team-b",
                token="scoped-token",
            )

        # Even after a failed request the shared adapter keeps its defaults.
        assert adapter.namespace == self.DEFAULT_NAMESPACE
        assert adapter.token == self.DEFAULT_TOKEN

    def test_ignore_exceptions_returns_response(self):
        session = FakeSession()

        def fail(method, url, headers=None, allow_redirects=True, **kwargs):
            response = requests.Response()
            response.status_code = 500
            response._content = b'{"errors": ["boom"]}'
            response.headers["Content-Type"] = "application/json"
            return response

        session.request = fail
        adapter = adapters.RawAdapter(
            base_uri=self.BASE_URI,
            session=session,
            ignore_exceptions=True,
            namespace=self.DEFAULT_NAMESPACE,
            token=self.DEFAULT_TOKEN,
        )

        response = adapter.get("v1/secret/data/broken", namespace="team-b")

        assert response.status_code == 500
        assert adapter.namespace == self.DEFAULT_NAMESPACE
        assert adapter.token == self.DEFAULT_TOKEN

    def test_clone_adapter_isolates_namespace_and_token(self):
        adapter, _ = self._adapter()
        original_session = adapter.session

        clone = adapter.clone(namespace="team-b", token="team-b-token")

        assert clone is not adapter
        assert isinstance(clone, adapters.RawAdapter)
        # Configuration is inherited, including the shared connection pool.
        assert clone.session is original_session
        assert clone.base_uri == adapter.base_uri
        assert clone.allow_redirects == adapter.allow_redirects
        # Only the requested identity differs.
        assert clone.namespace == "team-b"
        assert clone.token == "team-b-token"
        assert adapter.namespace == self.DEFAULT_NAMESPACE
        assert adapter.token == self.DEFAULT_TOKEN

        # Cloning without overrides produces an equivalent adapter.
        equivalent = adapter.clone()
        assert equivalent.namespace == self.DEFAULT_NAMESPACE
        assert equivalent.token == self.DEFAULT_TOKEN
        assert equivalent.session is original_session

    def test_clone_requests_send_their_own_identity(self):
        adapter, session = self._adapter()
        team_b = adapter.clone(namespace="team-b", token="team-b-token")
        # The clone reuses the parent's session/recorder.
        team_b.session = adapter.session

        adapter.get("v1/secret/data/a")
        team_b.get("v1/secret/data/b")

        first, second = session.calls
        assert first.url.endswith("/v1/secret/data/a")
        assert first.headers["X-Vault-Namespace"] == "team-a"
        assert first.headers["X-Vault-Token"] == self.DEFAULT_TOKEN
        assert second.url.endswith("/v1/secret/data/b")
        assert second.headers["X-Vault-Namespace"] == "team-b"
        assert second.headers["X-Vault-Token"] == "team-b-token"
        assert adapter.namespace == "team-a"

    def test_client_helper_methods_forward_per_request_identity(self):
        session = FakeSession()
        client = Client(
            url=self.BASE_URI,
            token=self.DEFAULT_TOKEN,
            namespace=self.DEFAULT_NAMESPACE,
            session=session,
        )

        client.adapter.request(
            "get",
            "v1/secret/data/from-client",
            namespace="team-b",
            token="client-scoped-token",
        )

        (sent,) = session.calls
        assert sent.url == f"{self.BASE_URI}/v1/secret/data/from-client"
        assert sent.headers["X-Vault-Namespace"] == "team-b"
        assert sent.headers["X-Vault-Token"] == "client-scoped-token"
        assert client.adapter.namespace == self.DEFAULT_NAMESPACE
        assert client.adapter.token == self.DEFAULT_TOKEN

    def test_interleaved_requests_keep_their_own_identity(self):
        """Two threads targeting different namespaces must never swap headers or paths."""
        adapter = adapters.RawAdapter(
            base_uri=self.BASE_URI,
            namespace="team-a",
            token="token-a",
            session=FakeSession(),
        )
        gate = threading.Event()
        errors = []

        def call_team_a():
            # Block until both threads are inside their request so they truly interleave.
            gate.wait(timeout=5)
            try:
                adapter.get("v1/secret/data/team-a-secret")
            except Exception as exc:  # pragma: no cover - surfaces failures on the main thread
                errors.append(exc)

        def call_team_b():
            gate.wait(timeout=5)
            try:
                adapter.get(
                    "v1/secret/data/team-b-secret",
                    namespace="team-b",
                    token="token-b",
                )
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        thread_a = threading.Thread(target=call_team_a)
        thread_b = threading.Thread(target=call_team_b)
        thread_a.start()
        thread_b.start()
        gate.set()
        thread_a.join()
        thread_b.join()

        assert not errors
        calls = {call.url.rsplit("/", 1)[-1]: call for call in adapter.session.calls}
        assert set(calls) == {"team-a-secret", "team-b-secret"}

        team_a_call = calls["team-a-secret"]
        assert team_a_call.url == f"{self.BASE_URI}/v1/secret/data/team-a-secret"
        assert team_a_call.headers["X-Vault-Namespace"] == "team-a"
        assert team_a_call.headers["X-Vault-Token"] == "token-a"

        team_b_call = calls["team-b-secret"]
        assert team_b_call.url == f"{self.BASE_URI}/v1/secret/data/team-b-secret"
        assert team_b_call.headers["X-Vault-Namespace"] == "team-b"
        assert team_b_call.headers["X-Vault-Token"] == "token-b"

        # The shared client keeps its original default configuration afterwards.
        assert adapter.namespace == "team-a"
        assert adapter.token == "token-a"
        # And a later plain call still uses those defaults.
        adapter.get("v1/secret/data/after")
        after = adapter.session.calls[-1]
        assert after.headers["X-Vault-Namespace"] == "team-a"
        assert after.headers["X-Vault-Token"] == "token-a"


class TestRequestScopedRedirects(TestCase):
    """Documents which authentication headers actually survive redirects."""

    BASE_URI = "https://vault.example:8200"

    def _adapter(self):
        return adapters.RawAdapter(
            base_uri=self.BASE_URI,
            token="vault-token",
            namespace="team-a",
            allow_redirects=True,
        )

    def test_same_target_redirect_keeps_every_authentication_header(self):
        path = "v1/secret/data/here"
        redirected = f"{self.BASE_URI}/v1/secret/data/there"
        adapter = self._adapter()

        with requests_mock.Mocker() as requests_mocker:
            requests_mocker.register_uri(
                method="GET",
                url=f"{self.BASE_URI}/{path}",
                status_code=307,
                headers={"Location": redirected},
            )
            requests_mocker.register_uri(method="GET", url=redirected)

            adapter.get(path, headers={"Authorization": "Bearer standard"})

            first, second = requests_mocker.request_history
            for request in (first, second):
                self.assertEqual(request.headers["X-Vault-Token"], "vault-token")
                self.assertEqual(request.headers["X-Vault-Namespace"], "team-a")
                self.assertEqual(request.headers["Authorization"], "Bearer standard")
            self.assertEqual(second.url, redirected)

    def test_different_target_redirect_strips_authorization_only(self):
        path = "v1/secret/data/here"
        redirected = "https://other-vault.example/redirected"
        adapter = self._adapter()

        with requests_mock.Mocker() as requests_mocker:
            requests_mocker.register_uri(
                method="GET",
                url=f"{self.BASE_URI}/{path}",
                status_code=307,
                headers={"Location": redirected},
            )
            requests_mocker.register_uri(method="GET", url=redirected)

            adapter.get(path, headers={"Authorization": "Bearer standard"})

            first, second = requests_mocker.request_history
            # Original request carries everything.
            self.assertEqual(first.headers["X-Vault-Token"], "vault-token")
            self.assertEqual(first.headers["X-Vault-Namespace"], "team-a")
            self.assertEqual(first.headers["Authorization"], "Bearer standard")
            # requests only knows how to strip the standard Authorization header.
            # Vault-specific headers are still sent to the foreign host.
            self.assertNotIn("Authorization", second.headers)
            self.assertEqual(second.headers["X-Vault-Token"], "vault-token")
            self.assertEqual(second.headers["X-Vault-Namespace"], "team-a")
            self.assertEqual(second.url, redirected)

    def test_per_request_identity_follows_redirect(self):
        path = "v1/secret/data/here"
        redirected = f"{self.BASE_URI}/v1/secret/data/there"
        adapter = self._adapter()

        with requests_mock.Mocker() as requests_mocker:
            requests_mocker.register_uri(
                method="GET",
                url=f"{self.BASE_URI}/{path}",
                status_code=307,
                headers={"Location": redirected},
            )
            requests_mocker.register_uri(method="GET", url=redirected)

            adapter.get(path, namespace="team-b", token="scoped-token")

            for request in requests_mocker.request_history:
                self.assertEqual(request.headers["X-Vault-Namespace"], "team-b")
                self.assertEqual(request.headers["X-Vault-Token"], "scoped-token")

        # Defaults remain intact after the redirected call.
        self.assertEqual(adapter.namespace, "team-a")
        self.assertEqual(adapter.token, "vault-token")
