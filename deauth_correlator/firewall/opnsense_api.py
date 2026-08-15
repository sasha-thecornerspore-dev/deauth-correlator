"""A deliberately small, read-only client for the OPNsense log API.

WHY THIS IS NARROW
------------------

OPNsense exposes its logs through one controller, reached as
``/api/diagnostics/log/{module}/{scope}``. That controller has four actions.
Three of them read. The fourth is ``clear``, and it empties the log file it is
pointed at.

A tool whose whole purpose is to preserve evidence has no business being one
typo away from destroying it. So this client does not offer a general way to
call the OPNsense API and then decline to use the dangerous parts. It builds
request paths from a pattern that ``clear`` cannot satisfy, and it checks the
finished URL against :data:`READ_ONLY_PATH` before the request is issued and
again on every redirect hop. There is no parameter, no configuration file and
no keyword argument that routes around that check.

The same reasoning drives the rest of the shape:

* Only GET and POST are ever issued, and POST only because the log query is a
  paginated search that OPNsense models as a POST. Nothing is created by it.
* ``session.trust_env = False``. A proxy named in the environment would
  otherwise receive the API key and secret, which are credentials to the
  firewall itself.
* Redirects are switched off and walked by hand, so a firewall (or something
  answering in its place) cannot bounce those credentials to another host.
* The response size is capped. A log query that answers with something
  enormous is a reason to stop rather than to fill the disk.

TLS
---

An OPNsense box usually presents a self-signed certificate, so the honest
options are to trust its CA explicitly or to pin the certificate. Both are
supported, and which one was used is recorded in the fetch provenance, because
"the logs came from the firewall" is a claim about identity and an unverified
connection cannot support it. Turning verification off entirely is possible and
is recorded in the output as ``UNVERIFIED`` in as many words.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from .. import __tool_name__, __version__

#: Every request this client can issue. Anchored at both ends, no alternation
#: that admits an action name other than "export", and "clear" is unreachable
#: because it is not in the pattern. ``{module}/{scope}`` are the two path
#: components OPNsense uses to name a log - "core/kea", "core/system".
READ_ONLY_PATH = re.compile(
    r"^/api/(?:"
    r"diagnostics/log/[A-Za-z0-9_]{1,32}/[A-Za-z0-9_.\-]{1,64}(?:/export)?"
    r"|core/system/status"
    r"|core/firmware/status"
    r")$"
)

#: A response bigger than this is refused rather than buffered. A day of DHCP
#: logging is a few megabytes; 256 MiB is far past anything legitimate.
MAX_RESPONSE_BYTES = 256 * 1024 * 1024

#: OPNsense caps rowCount at 9999. Ask for a round number below it.
PAGE_ROWS = 5000

#: Refuse to page for ever if the firewall keeps answering with full pages.
MAX_PAGES = 400

USER_AGENT = (f"{__tool_name__}/{__version__} "
              f"(+https://github.com/sasha-thecornerspore-dev/deauth-correlator)")


class FirewallError(RuntimeError):
    """Base class, so a caller can catch everything from this module at once."""


class FirewallUnavailable(FirewallError):
    """The firewall could not be reached, or answered in a way we will not use."""


class FirewallAuthError(FirewallError):
    """The API key or secret was rejected."""


class FirewallRefused(FirewallError):
    """This client refused to issue the request. Always a bug or an attack."""


@dataclass
class FirewallConfig:
    """How to reach the firewall. The secret is never persisted anywhere."""

    host: str = ""
    port: int = 443
    key: str = ""
    secret: str = field(default="", repr=False)
    #: True to verify against the system CA store, a path to a CA bundle, or
    #: False to skip verification entirely.
    verify: bool | str = True
    #: "sha256/AA:BB:.." to pin the certificate instead. Takes precedence.
    fingerprint: str = ""
    timeout: float = 30.0

    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    def tls_description(self) -> str:
        """One phrase for the provenance record. Says 'UNVERIFIED' when it is."""
        if self.fingerprint:
            return f"pinned certificate {self.fingerprint}"
        if self.verify is False:
            return ("UNVERIFIED - the certificate was not checked, so this "
                    "connection does not establish which machine answered")
        if isinstance(self.verify, str):
            return f"verified against the CA bundle at {self.verify}"
        return "verified against the system certificate store"

    def is_configured(self) -> bool:
        return bool(self.host and self.key and self.secret)


def _requests():
    """Import requests lazily; it is an optional dependency of the package."""
    try:
        import requests
    except ImportError as exc:                                   # pragma: no cover
        raise FirewallUnavailable(
            "reading logs from the firewall needs the 'requests' package, which "
            "is not installed in this Python. Install it with 'pip install "
            "requests', or export the logs from the firewall by hand.") from exc
    return requests


def check_url(url: str, host: str, port: int) -> None:
    """Refuse anything that is not a read of the log API on the configured host.

    Called on the URL about to be fetched and again on every redirect target,
    because a redirect is how a request that started out fine ends up somewhere
    else carrying the same Authorization header.
    """
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise FirewallRefused(
            f"refusing to fetch {url}: the firewall API is only used over HTTPS. "
            f"The API key and secret would otherwise cross the network in clear.")
    if (parts.hostname or "").lower() != host.lower():
        raise FirewallRefused(
            f"refusing to contact {parts.hostname or 'an unnamed host'}: this "
            f"client only talks to the firewall you named ({host}), and it will "
            f"not follow a redirect anywhere else.")
    try:
        actual_port = parts.port or 443
    except ValueError:
        raise FirewallRefused(
            f"refusing to fetch {url}: it does not name a valid port.") from None
    if actual_port != port:
        raise FirewallRefused(
            f"refusing to fetch {url}: it names port {actual_port} rather than "
            f"the {port} you configured.")
    if not READ_ONLY_PATH.match(parts.path):
        raise FirewallRefused(
            f"refusing to request {parts.path!r}. This client can only read "
            f"logs. In particular the OPNsense log API's 'clear' action empties "
            f"the log it is pointed at, and nothing here is able to reach it.")


class OpnsenseClient:
    """Read-only access to the OPNsense log API."""

    def __init__(self, config: FirewallConfig):
        if not config.host:
            raise FirewallUnavailable("no firewall address was given.")
        if not (config.key and config.secret):
            raise FirewallUnavailable(
                "an OPNsense API key and secret are needed. Create one under "
                "System > Access > Users > (your user) > API keys; it downloads "
                "as a text file holding both halves.")
        self.config = config
        self._session = None

    # -- plumbing --------------------------------------------------------

    def _ensure_session(self):
        if self._session is not None:
            return self._session
        requests = _requests()
        session = requests.Session()
        # A proxy from the environment would receive credentials to the
        # firewall. Never inherit one.
        session.trust_env = False
        session.auth = (self.config.key, self.config.secret)
        session.headers.update({"User-Agent": USER_AGENT,
                                "Accept": "application/json"})
        if self.config.fingerprint:
            session.mount("https://", _fingerprint_adapter(self.config.fingerprint))
        self._session = session
        return session

    def _request(self, method: str, path: str, data: dict | None = None):
        """Issue one checked request, walking redirects by hand."""
        if method not in ("GET", "POST"):
            raise FirewallRefused(
                f"refusing to issue a {method} request. This client reads.")
        requests = _requests()
        session = self._ensure_session()
        url = urlunsplit(("https", f"{self.config.host}:{self.config.port}",
                          path, "", ""))
        check_url(url, self.config.host, self.config.port)

        verify = self.config.verify
        if self.config.fingerprint:
            # urllib3 does the pinning; its own chain check would reject the
            # self-signed certificate the pin exists to accept.
            verify = False

        for _ in range(5):
            try:
                response = session.request(
                    method, url, data=data, timeout=self.config.timeout,
                    allow_redirects=False, verify=verify, stream=True)
            except requests.exceptions.SSLError as exc:
                raise FirewallUnavailable(
                    f"the TLS connection to {self.config.host} was refused: "
                    f"{exc}. An OPNsense box normally presents a self-signed "
                    f"certificate - either trust its CA with --firewall-ca, pin "
                    f"the certificate with --firewall-fingerprint, or use "
                    f"--firewall-insecure and accept that the connection then "
                    f"proves nothing about which machine answered.") from exc
            except requests.exceptions.RequestException as exc:
                raise FirewallUnavailable(
                    f"could not reach {self.config.host}:{self.config.port}: "
                    f"{exc}") from exc

            if response.status_code in (301, 302, 303, 307, 308):
                target = response.headers.get("Location", "")
                response.close()
                if not target:
                    raise FirewallUnavailable(
                        "the firewall answered with a redirect that named no "
                        "destination.")
                url = requests.compat.urljoin(url, target)
                check_url(url, self.config.host, self.config.port)
                continue

            if response.status_code in (401, 403):
                response.close()
                raise FirewallAuthError(
                    f"the firewall rejected the API key ({response.status_code}). "
                    f"Check that the key and secret are the pair downloaded "
                    f"together, and that the user they belong to has access to "
                    f"Diagnostics: Log.")
            if response.status_code == 404:
                response.close()
                raise FirewallUnavailable(f"{path} does not exist on this firewall.")
            if response.status_code >= 400:
                response.close()
                raise FirewallUnavailable(
                    f"the firewall answered {response.status_code} for {path}.")
            return self._read_json(response, path)

        raise FirewallUnavailable(
            "the firewall kept redirecting; giving up after five hops.")

    @staticmethod
    def _read_json(response, path: str) -> dict:
        payload = bytearray()
        try:
            for chunk in response.iter_content(64 * 1024):
                payload.extend(chunk)
                if len(payload) > MAX_RESPONSE_BYTES:
                    raise FirewallUnavailable(
                        f"the answer to {path} is larger than "
                        f"{MAX_RESPONSE_BYTES // (1024 * 1024)} MiB. Narrow the "
                        f"time range rather than pulling the whole log.")
        finally:
            response.close()
        try:
            return json.loads(payload.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            head = payload[:200].decode("utf-8", errors="replace")
            raise FirewallUnavailable(
                f"the firewall answered {path} with something that is not JSON "
                f"({exc}). It began: {head!r}. This usually means the address "
                f"belongs to something other than an OPNsense API.") from exc

    # -- what a caller actually uses -------------------------------------

    def identify(self) -> dict:
        """Read the firewall's name and version, to record in the provenance."""
        data = self._request("GET", "/api/core/system/status")
        return data if isinstance(data, dict) else {}

    def log_page(self, module: str, scope: str, page: int,
                 rows: int = PAGE_ROWS, search: str = "") -> dict:
        """One page of a log, newest first. ``module``/``scope`` name the log."""
        _check_component(module, "module")
        _check_component(scope, "scope")
        body = {"current": str(page), "rowCount": str(rows)}
        if search:
            body["searchPhrase"] = search
        return self._request("POST", f"/api/diagnostics/log/{module}/{scope}",
                             data=body)

    def log_exists(self, module: str, scope: str) -> bool:
        """Whether this firewall has that log at all, without reading it."""
        try:
            self.log_page(module, scope, page=1, rows=1)
            return True
        except FirewallUnavailable:
            return False

    def close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False


def _check_component(value: str, what: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", value or ""):
        raise FirewallRefused(
            f"{value!r} is not a usable log {what}. It may contain letters, "
            f"digits, dot, dash and underscore only - anything else could "
            f"change which endpoint the request reaches.")


def _fingerprint_adapter(fingerprint: str):
    """An adapter that checks the certificate fingerprint on every connection.

    urllib3's ``assert_fingerprint`` is used rather than a check done once at
    the start, so a connection that is re-established mid-fetch is held to the
    same pin as the first one.
    """
    requests = _requests()
    from urllib3.poolmanager import PoolManager

    digest = fingerprint.strip()
    for prefix in ("sha256/", "sha256:", "SHA256:", "SHA256/"):
        if digest.startswith(prefix):
            digest = digest[len(prefix):]
            break
    digest = digest.replace(":", "").replace(" ", "").lower()
    if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
        raise FirewallUnavailable(
            f"{fingerprint!r} is not a SHA-256 certificate fingerprint. Expected "
            f"64 hexadecimal characters, optionally colon-separated and "
            f"optionally prefixed 'sha256:'.")

    class _FingerprintAdapter(requests.adapters.HTTPAdapter):
        def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
            kwargs["assert_fingerprint"] = digest
            self.poolmanager = PoolManager(
                num_pools=connections, maxsize=maxsize, block=block, **kwargs)

    return _FingerprintAdapter()


def certificate_fingerprint(host: str, port: int = 443,
                            timeout: float = 10.0) -> str:
    """Read the SHA-256 fingerprint the firewall presents, so it can be pinned.

    This is a convenience for setting the pin up in the first place, and it
    verifies nothing on its own - whoever answers gets to state their own
    fingerprint. Read it once over a network you trust, then compare it against
    the value shown in the firewall's own web interface under System > Trust >
    Certificates before pinning it.
    """
    import hashlib

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except OSError as exc:
        raise FirewallUnavailable(
            f"could not open a TLS connection to {host}:{port}: {exc}") from exc
    if not der:
        raise FirewallUnavailable(f"{host}:{port} presented no certificate.")
    digest = hashlib.sha256(der).hexdigest()
    return "sha256:" + ":".join(digest[i:i + 2].upper()
                                for i in range(0, len(digest), 2))
