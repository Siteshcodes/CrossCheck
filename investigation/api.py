"""One local JSON endpoint. Files arrive as bytes, never server-side user paths."""

import base64
from http.server import BaseHTTPRequestHandler
import threading

from .llm import AnnotationExtractor, LLMFailure
from .models import InvalidInput, strict_json
from .http_support import BoundedHTTPServer, HTTPProblem, MAX_REQUEST_BYTES, read_body, send_json, error_payload


REQUEST_KEYS = {"message", "claims_annotation", "eml_base64", "original_receiver_export"}


def investigate_request(request, engine, allow_annotations=False):
    if not isinstance(request, dict) or not set(request) <= REQUEST_KEYS:
        raise InvalidInput("Expected JSON object with message, optional eml_base64 and original_receiver_export; server paths and source overrides are forbidden")
    message = request.get("message")
    data = request.get("eml_base64")
    eml = None
    if data is not None:
        if not isinstance(data, str) or len(data) > 2_666_668:
            raise InvalidInput("eml_base64 must be a bounded base64 string")
        try:
            eml = base64.b64decode(data, validate=True)
        except (ValueError, TypeError) as exc:
            raise InvalidInput("Invalid eml_base64") from exc
    selected = engine
    if "claims_annotation" in request:
        if not allow_annotations:
            raise InvalidInput("Analyst annotations are disabled; this endpoint uses LLM extraction")
        from .engine import InvestigationEngine
        selected = InvestigationEngine(AnnotationExtractor(request["claims_annotation"]), engine.policy, engine.domain, engine.headers, engine.explainer)
    return selected.investigate(message, eml, request.get("original_receiver_export", False),
                                input_origin="annotated_api_input" if "claims_annotation" in request else "user_supplied")


def make_server(engine, host="127.0.0.1", port=8000, allow_annotations=False):
    investigations = threading.BoundedSemaphore(4)
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def send_json(self, code, payload):
            send_json(self, code, payload)

        def do_POST(self):
            if self.path != "/investigate":
                return self.send_json(404, error_payload('not_found', 'UnknownEndpoint', 'Use POST /investigate'))
            try:
                raw = read_body(self)
                request = strict_json(raw.decode("utf-8"))
                if not investigations.acquire(blocking=False):
                    return self.send_json(503, error_payload('busy', 'CapacityExceeded', 'Investigation capacity reached; retry shortly.'))
                try:
                    result = investigate_request(request, engine, allow_annotations)
                finally:
                    investigations.release()
                self.send_json(200, result)
            except HTTPProblem as exc:
                self.send_json(exc.code, error_payload('invalid_input', 'InvalidRequest', str(exc)))
            except TimeoutError:
                self.send_json(408, error_payload('request_timeout', 'RequestTimeout', 'Request body timed out'))
            except (InvalidInput, ValueError, UnicodeError, TypeError) as exc:
                message = str(exc) if isinstance(exc, InvalidInput) else 'Malformed JSON or invalid request encoding/types'
                self.send_json(400, error_payload('invalid_input', type(exc).__name__, message))
            except LLMFailure as exc:
                safe = {k: v for k, v in exc.evidence.items() if k in {'http_status','request_id','network_request_made','latency_ms','validation_stage'} and isinstance(v, (str, int, float, bool, type(None)))}
                message = 'Live claim extraction failed. Check server configuration or retry later.'
                if safe.get('network_request_made') is False:
                    message = 'Live extraction requires server-side OPENAI_API_KEY configuration.'
                payload = error_payload('extraction_failed', 'LLMFailure', message, claims=[])
                payload['error']['provider_evidence'] = safe
                self.send_json(502, payload)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception:
                self.send_json(500, error_payload('investigation_failed', 'InternalError', 'Investigation failed unexpectedly; no result was substituted.'))

        def do_GET(self):
            self.send_json(404, error_payload('not_found', 'UnknownEndpoint', 'Use POST /investigate'))

        def log_message(self, format, *args):
            # Access metadata only. Never log messages, raw emails or API credentials.
            return

    return BoundedHTTPServer((host, port), Handler)
