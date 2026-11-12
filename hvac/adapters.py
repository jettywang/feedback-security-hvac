"""
HTTP Client Library Adapters

"""
from abc import ABCMeta, abstractmethod

import requests
import requests.exceptions

from hvac import utils
from hvac.constants.client import DEFAULT_URL

# Sentinel used to distinguish "parameter not supplied for this request" from
# an explicit ``None`` (which means "do not send the header on this request").
_UNSET = object()


class Adapter(metaclass=ABCMeta):
    """Abstract base class used when constructing adapters for use with the Client class."""

    @classmethod
    def from_adapter(
        cls,
        adapter,
    ):
        """Create a new adapter based on an existing Adapter instance.
        This can be used to create a new type of adapter that inherits the properties of an existing one.

        :param adapter: The existing Adapter instance.
        :type adapter: hvac.Adapters.Adapter
        """

        return cls(
            base_uri=adapter.base_uri,
            token=adapter.token,
            cert=adapter._kwargs.get("cert"),
            verify=adapter._kwargs.get("verify"),
            timeout=adapter._kwargs.get("timeout"),
            proxies=adapter._kwargs.get("proxies"),
            allow_redirects=adapter.allow_redirects,
            session=adapter.session,
            namespace=adapter.namespace,
            ignore_exceptions=adapter.ignore_exceptions,
            strict_http=adapter.strict_http,
            request_header=adapter.request_header,
        )

    def __init__(
        self,
        base_uri=DEFAULT_URL,
        token=None,
        cert=None,
        verify=True,
        timeout=30,
        proxies=None,
        allow_redirects=True,
        session=None,
        namespace=None,
        ignore_exceptions=False,
        strict_http=False,
        request_header=True,
    ):
        """Create a new request adapter instance.

        :param base_uri: Base URL for the Vault instance being addressed.
        :type base_uri: str
        :param token: Authentication token to include in requests sent to Vault.
        :type token: str
        :param cert: Certificates for use in requests sent to the Vault instance. This should be a tuple with the
            certificate and then key.
        :type cert: tuple
        :param verify: Either a boolean to indicate whether TLS verification should be performed when sending requests to Vault,
            or a string pointing at the CA bundle to use for verification. See http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification.
        :type verify: Union[bool,str]
        :param timeout: The timeout value for requests sent to Vault.
        :type timeout: int
        :param proxies: Proxies to use when preforming requests.
            See: http://docs.python-requests.org/en/master/user/advanced/#proxies
        :type proxies: dict
        :param allow_redirects: Whether to follow redirects when sending requests to Vault.
        :type allow_redirects: bool
        :param session: Optional session object to use when performing request.
        :type session: request.Session
        :param namespace: Optional Vault Namespace.
        :type namespace: str
        :param ignore_exceptions: If True, _always_ return the response object for a given request. I.e., don't raise an exception
            based on response status code, etc.
        :type ignore_exceptions: bool
        :param strict_http: If True, use only standard HTTP verbs in request with additional params, otherwise process as is
        :type strict_http: bool
        :param request_header: If true, add the X-Vault-Request header to all requests to protect against SSRF vulnerabilities.
        :type request_header: bool
        """
        if not session:
            session = requests.Session()
            session.cert, session.verify, session.proxies = cert, verify, proxies
        # fix for issue 991 using session verify if set
        else:
            if session.verify:
                # need to set the variable and not assign it to self so it is properly passed in kwargs
                verify = session.verify
            if session.cert:
                cert = session.cert
            if session.proxies:
                proxies = session.proxies

        self.base_uri = base_uri
        self.token = token
        self.namespace = namespace
        self.session = session
        self.allow_redirects = allow_redirects
        self.ignore_exceptions = ignore_exceptions
        self.strict_http = strict_http
        self.request_header = request_header

        self._kwargs = {
            "cert": cert,
            "verify": verify,
            "timeout": timeout,
            "proxies": proxies,
        }

    def clone(self, **kwargs):
        """Create a copy of this adapter with optional per-request overrides.

        The returned adapter is the same class as ``self`` and inherits every
        configuration value (including the shared ``requests`` session), but
        can be given a different ``namespace`` and/or ``token`` without
        touching the adapter it was cloned from. This makes it safe to talk to
        multiple Vault namespaces from one client: give each namespace its own
        cloned adapter instead of mutating a shared adapter's attributes.

        :param kwargs: Any :py:meth:`Adapter.__init__` parameter to override on
            the clone, most commonly ``namespace`` and ``token``.
        :type kwargs: dict
        :return: A new adapter of the same type as this instance.
        :rtype: hvac.adapters.Adapter
        """
        clone_kwargs = {
            "base_uri": self.base_uri,
            "token": self.token,
            "cert": self._kwargs.get("cert"),
            "verify": self._kwargs.get("verify"),
            "timeout": self._kwargs.get("timeout"),
            "proxies": self._kwargs.get("proxies"),
            "allow_redirects": self.allow_redirects,
            "session": self.session,
            "namespace": self.namespace,
            "ignore_exceptions": self.ignore_exceptions,
            "strict_http": self.strict_http,
            "request_header": self.request_header,
        }
        clone_kwargs.update(kwargs)
        return self.__class__(**clone_kwargs)

    @staticmethod
    def urljoin(*args):
        """Joins given arguments into a url. Trailing and leading slashes are stripped for each argument.

        :param args: Multiple parts of a URL to be combined into one string.
        :type args: str | unicode
        :return: Full URL combining all provided arguments
        :rtype: str | unicode
        """

        return "/".join(map(lambda x: str(x).strip("/"), args))

    def close(self):
        """Close the underlying Requests session."""
        self.session.close()

    def get(self, url, **kwargs):
        """Performs a GET request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request("get", url, **kwargs)

    def post(self, url, **kwargs):
        """Performs a POST request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request("post", url, **kwargs)

    def put(self, url, **kwargs):
        """Performs a PUT request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request("put", url, **kwargs)

    def delete(self, url, **kwargs):
        """Performs a DELETE request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request("delete", url, **kwargs)

    def list(self, url, **kwargs):
        """Performs a LIST request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request("list", url, **kwargs)

    def head(self, url, **kwargs):
        """Performs a HEAD request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request("head", url, **kwargs)

    def login(self, url, use_token=True, **kwargs):
        """Perform a login request.

        Associated request is typically to a path prefixed with "/v1/auth") and optionally stores the client token sent
            in the resulting Vault response for use by the :py:meth:`hvac.adapters.Adapter` instance under the _adapter
            Client attribute.

        :param url: Path to send the authentication request to.
        :type url: str | unicode
        :param use_token: if True, uses the token in the response received from the auth request to set the "token"
            attribute on the the :py:meth:`hvac.adapters.Adapter` instance under the _adapter Client attribute.
        :type use_token: bool
        :param kwargs: Additional keyword arguments to include in the params sent with the request.
        :type kwargs: dict
        :return: The response of the auth request.
        :rtype: requests.Response
        """
        response = self.post(url, **kwargs)

        if use_token:
            self.token = self.get_login_token(response)

        return response

    @abstractmethod
    def get_login_token(self, response):
        """Extracts the client token from a login response.

        :param response: The response object returned by the login method.
        :return: A client token.
        :rtype: str
        """
        return NotImplementedError

    @abstractmethod
    def request(
        self,
        method,
        url,
        headers=None,
        raise_exception=True,
        namespace=_UNSET,
        token=_UNSET,
        **kwargs,
    ):
        """Main method for routing HTTP requests to the configured Vault base_uri. Intended to be implement by subclasses.

        :param method: HTTP method to use with the request. E.g., GET, POST, etc.
        :type method: str
        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param headers: Additional headers to include with the request.
        :type headers: dict
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :param raise_exception: If True, raise an exception via utils.raise_for_error(). Set this parameter to False to
            bypass this functionality.
        :type raise_exception: bool
        :param namespace: Vault namespace to use for this request only. Defaults to the adapter's configured
            ``namespace`` when not supplied. Pass a string to override it for this request, or pass ``None``
            explicitly to suppress the ``X-Vault-Namespace`` header even when the adapter has one configured.
            The adapter's ``namespace`` attribute is never modified, so this is safe for concurrent requests.
        :type namespace: str | None
        :param token: Vault token to use for this request only. Defaults to the adapter's configured ``token``
            when not supplied. Pass a string to override it for this request, or pass ``None`` explicitly to
            suppress the ``X-Vault-Token`` header even when the adapter has a token configured.
            The adapter's ``token`` attribute is never modified, so this is safe for concurrent requests.
        :type token: str | None
        :return: The response of the request.
        :rtype: requests.Response
        """
        raise NotImplementedError


class RawAdapter(Adapter):
    """
    The RawAdapter adapter class.
    This adapter adds Vault-specific headers as required and optionally raises exceptions on errors,
    but always returns Response objects for requests.
    """

    def _raise_for_error(self, method: str, url: str, response: requests.Response):
        msg = json = text = errors = None
        try:
            text = response.text
        except Exception:
            pass

        if response.headers.get("Content-Type") == "application/json":
            try:
                json = response.json()
            except Exception:
                pass
            else:
                errors = json.get("errors")

        if errors is None:
            msg = text

        utils.raise_for_error(
            method,
            url,
            response.status_code,
            msg,
            errors=errors,
            text=text,
            json=json,
        )

    def get_login_token(self, response):
        """Extracts the client token from a login response.

        :param response: The response object returned by the login method.
        :type response: requests.Response
        :return: A client token.
        :rtype: str
        """
        response_json = response.json()
        return response_json["auth"]["client_token"]

    def request(
        self,
        method,
        url,
        headers=None,
        raise_exception=True,
        namespace=_UNSET,
        token=_UNSET,
        **kwargs,
    ):
        """Main method for routing HTTP requests to the configured Vault base_uri.

        :param method: HTTP method to use with the request. E.g., GET, POST, etc.
        :type method: str
        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param headers: Additional headers to include with the request.
        :type headers: dict
        :param raise_exception: If True, raise an exception via utils.raise_for_error(). Set this parameter to False to
            bypass this functionality.
        :type raise_exception: bool
        :param namespace: Vault namespace for this request only. When not supplied, the adapter's configured
            ``namespace`` is used. A string overrides it for this request; ``None`` suppresses the
            ``X-Vault-Namespace`` header. The adapter's ``namespace`` attribute is left untouched.
        :type namespace: str | None
        :param token: Vault token for this request only. When not supplied, the adapter's configured ``token``
            is used. A string overrides it for this request; ``None`` suppresses the ``X-Vault-Token`` header.
            The adapter's ``token`` attribute is left untouched.
        :type token: str | None
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        while "//" in url:
            # Vault CLI treats a double forward slash ('//') as a single forward slash for a given path.
            # To avoid issues with the requests module's redirection logic, we perform the same translation here.
            url = url.replace("//", "/")

        url = self.urljoin(self.base_uri, url)

        if not headers:
            headers = {}

        if self.request_header:
            headers["X-Vault-Request"] = "true"

        # Resolve the request-scoped values into local variables so the shared
        # adapter attributes are never mutated and concurrent requests cannot
        # observe each other's namespace or token.
        request_token = self.token if token is _UNSET else token
        request_namespace = self.namespace if namespace is _UNSET else namespace

        if request_token:
            headers["X-Vault-Token"] = request_token

        if request_namespace:
            headers["X-Vault-Namespace"] = request_namespace

        wrap_ttl = kwargs.pop("wrap_ttl", None)
        if wrap_ttl:
            headers["X-Vault-Wrap-TTL"] = str(wrap_ttl)

        _kwargs = self._kwargs.copy()
        _kwargs.update(kwargs)

        if self.strict_http and method.lower() in ("list",):
            # Entry point for standard HTTP substitution
            params = _kwargs.get("params", {})
            if method.lower() == "list":
                method = "get"
                params.update({"list": "true"})
            _kwargs["params"] = params

        response = self.session.request(
            method=method,
            url=url,
            headers=headers,
            allow_redirects=self.allow_redirects,
            **_kwargs
        )

        if not response.ok and (raise_exception and not self.ignore_exceptions):
            self._raise_for_error(method, url, response)

        return response


class JSONAdapter(RawAdapter):
    """
    The JSONAdapter adapter class.
    This adapter works just like the RawAdapter adapter except that HTTP 200 responses are returned as JSON dicts.
    All non-200 responses are returned as Response objects.
    """

    def get_login_token(self, response):
        """Extracts the client token from a login response.

        :param response: The response object returned by the login method.
        :type response: dict | requests.Response
        :return: A client token.
        :rtype: str
        """
        return response["auth"]["client_token"]

    def request(self, *args, **kwargs):
        """Main method for routing HTTP requests to the configured Vault base_uri.

        :param args: Positional arguments to pass to RawAdapter.request.
        :type args: list
        :param kwargs: Keyword arguments to pass to RawAdapter.request.
        :type kwargs: dict
        :return: Dict on HTTP 200 with JSON body, otherwise the response object.
        :rtype: dict | requests.Response
        """
        response = super().request(*args, **kwargs)
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                pass

        return response


# Retaining the legacy name
Request = RawAdapter
