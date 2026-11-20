"""Shared request framing and bounded local HTTP workers."""
from http.server import ThreadingHTTPServer
import json
import logging
import threading
import time
import uuid
from urllib.parse import urlsplit

MAX_REQUEST_BYTES = 4_000_000
REQUEST_TIMEOUT = 15
LOGGER = logging.getLogger('crosscheck.http')


class HTTPProblem(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def read_body(handler):
    hosts = handler.headers.get_all('Host', [])
    origins = handler.headers.get_all('Origin', [])
    if len(hosts) != 1 or len(origins) > 1:
        raise HTTPProblem(400, 'Exactly one Host and at most one Origin header are required')
    try:
        host = urlsplit('//'+hosts[0])
        if host.username is not None or host.password is not None or host.path or host.query or host.fragment or not host.hostname:
            raise ValueError('Invalid Host')
        port = host.port
        if handler.server.server_address[0] in {'127.0.0.1','::1'} and host.hostname not in {'localhost','127.0.0.1','::1'}:
            raise HTTPProblem(403, 'Local server requires a loopback Host')
        if origins:
            origin = urlsplit(origins[0])
            default_port = 443 if origin.scheme == 'https' else 80
            if (origin.scheme not in {'http','https'} or origin.hostname != host.hostname
                    or origin.username is not None or origin.password is not None
                    or origin.path or origin.query or origin.fragment
                    or (origin.port or default_port) != (port or default_port)):
                raise HTTPProblem(403, 'Cross-origin investigation requests are forbidden')
    except HTTPProblem:
        raise
    except ValueError:
        raise HTTPProblem(400, 'Invalid Host or Origin header') from None
    if handler.headers.get('Transfer-Encoding'):
        raise HTTPProblem(400, 'Transfer-Encoding is unsupported')
    lengths = handler.headers.get_all('Content-Length', [])
    if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0]) > 10:
        raise HTTPProblem(400, 'Exactly one bounded numeric Content-Length is required')
    size = int(lengths[0])
    if not 0 < size <= MAX_REQUEST_BYTES:
        raise HTTPProblem(413, 'Request body too large or empty')
    if handler.headers.get_content_type() != 'application/json':
        raise HTTPProblem(415, 'Content-Type must be application/json')
    deadline = time.monotonic() + REQUEST_TIMEOUT
    chunks, received = [], 0
    while received < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Request body deadline exhausted')
        handler.connection.settimeout(remaining)
        chunk = handler.rfile.read1(min(65536, size-received))
        if not chunk: break
        chunks.append(chunk)
        received += len(chunk)
    handler.connection.settimeout(REQUEST_TIMEOUT)
    raw = b''.join(chunks)
    if len(raw) != size:
        raise HTTPProblem(400, 'Incomplete request body')
    return raw


def error_payload(status, kind, message, **extra):
    return {'status': status, 'error': {'type': kind, 'message': message}, **extra}


def send_json(handler, code, payload):
    request_id = uuid.uuid4().hex
    body = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode('utf-8')
    handler.send_response(code)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Content-Length', str(len(body)))
    handler.send_header('Cache-Control', 'no-store')
    handler.send_header('X-Content-Type-Options', 'nosniff')
    handler.send_header('X-Request-ID', request_id)
    if code == 503: handler.send_header('Retry-After', '2')
    handler.end_headers()
    try:
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError, TimeoutError):
        pass
    # No URL/query, message, headers, provider payload or exception text.
    LOGGER.info('response request_id=%s status=%s bytes=%s', request_id, code, len(body))


class BoundedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, max_workers=8):
        self.slots = threading.BoundedSemaphore(max_workers)
        super().__init__(address, handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(REQUEST_TIMEOUT)  # Includes request-line/header reads.
        return connection, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            payload = json.dumps(error_payload('busy', 'CapacityExceeded', 'Server is busy; retry shortly.')).encode()
            try:
                request.settimeout(.1)
                request.sendall(b'HTTP/1.0 503 Service Unavailable\r\nContent-Type: application/json\r\nRetry-After: 2\r\nCache-Control: no-store\r\nContent-Length: '+str(len(payload)).encode()+b'\r\n\r\n'+payload)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        LOGGER.error('HTTP worker failed; request details omitted')
