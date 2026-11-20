"""Small shared outbound HTTPS policy; no dependency on investigation imports."""
from contextlib import contextmanager
from contextvars import ContextVar
from http.client import HTTPSConnection
import ipaddress
import errno
import socket
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, build_opener


class UnsafeURL(ValueError):
    pass


_budget = ContextVar('crosscheck_outbound_budget', default=None)


@contextmanager
def investigation_budget(max_requests=32, seconds=90):
    """Per invocation, never shared across concurrent users; nested routes share it."""
    if _budget.get() is not None:
        yield
        return
    token = _budget.set({'remaining': max_requests, 'deadline': time.monotonic()+seconds})
    try:
        yield
    finally:
        _budget.reset(token)


def remaining_timeout(timeout):
    budget = _budget.get()
    if budget is not None:
        remaining = budget['deadline'] - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Investigation outbound time budget exhausted')
        return min(timeout, remaining)
    return timeout


def checked_https_url(url, allowed_hosts=None):
    if not isinstance(url, str) or any(ord(c) < 33 or ord(c) == 127 for c in url) or '\\' in url:
        raise UnsafeURL('Invalid HTTPS URL')
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.port not in (None, 443) or parsed.fragment):
        raise UnsafeURL('Only credential-free HTTPS on port 443 is allowed')
    host = parsed.hostname.lower()
    if allowed_hosts is not None and host not in allowed_hosts:
        raise UnsafeURL('Redirect host is outside the selected authority')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if '.' not in host or host.endswith(('.localhost', '.local', '.internal')) or '%' in host:
            raise UnsafeURL('Non-public host is forbidden')
    else:
        if not address.is_global:
            raise UnsafeURL('Non-public IP address is forbidden')
    return parsed


def public_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    """Resolve once and connect to a checked sockaddr: no second DNS/rebinding window."""
    host, port = address
    answers = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    if not answers or any(not ipaddress.ip_address(a[4][0]).is_global for a in answers):
        raise UnsafeURL('Authority resolves to a non-public address')
    last_error = None
    for family, kind, proto, _, sockaddr in answers:
        sock = socket.socket(family, kind, proto)
        try:
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(remaining_timeout(timeout))
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise last_error or OSError('No usable public address')


class PublicHTTPSConnection(HTTPSConnection):
    def connect(self):
        self._create_connection = public_connection
        super().connect()  # TLS still verifies the original hostname and CA chain.


class PublicHTTPSHandler(HTTPSHandler):
    def https_open(self, request):
        checked_https_url(request.full_url)
        budget = _budget.get()
        if budget is not None:
            if budget['remaining'] <= 0:
                raise OSError('Investigation outbound request budget exhausted')
            budget['remaining'] -= 1
        request.timeout = remaining_timeout(request.timeout)
        return self.do_open(PublicHTTPSConnection, request, context=self._context)


def secure_opener(*handlers):
    # An environment HTTP proxy could bypass address checks. Explicit direct TLS only.
    return build_opener(ProxyHandler({}), PublicHTTPSHandler(), *handlers)


def bounded_read(response, max_bytes):
    chunks, size = [], 0
    while size <= max_bytes:
        remaining_timeout(15)
        chunk = response.read1(min(65536, max_bytes+1-size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b''.join(chunks)


def open_get(opener, request, timeout, attempts):
    """At most two GET attempts, one 250 ms backoff. Never retry a paid POST."""
    for attempt in range(2):
        try:
            try:
                response = opener.open(request, timeout=remaining_timeout(timeout))
            except HTTPError as exc:
                response = exc
            status = response.status
            retry = status in {429, 502, 503, 504} and attempt == 0
            attempts.append({'attempt': attempt+1, 'http_status': status, 'retry': retry})
            if not retry:
                return response
            response.close()
        except (TimeoutError, URLError, ConnectionError) as exc:
            reason = getattr(exc, 'reason', exc)
            transient = isinstance(reason, (TimeoutError, ConnectionError)) or (
                isinstance(reason, OSError) and reason.errno in {errno.ECONNRESET, errno.ECONNREFUSED, errno.ETIMEDOUT, socket.EAI_AGAIN})
            retry = attempt == 0 and transient
            attempts.append({'attempt': attempt+1, 'error_type': type(exc).__name__, 'retry': retry})
            if not retry:
                raise
        remaining_timeout(.25)
        time.sleep(.25)
    raise RuntimeError('Unreachable GET retry state')
