"""One local JSON endpoint. Files arrive as bytes, never server-side user paths."""

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json

from .llm import AnnotationExtractor, LLMFailure
from .models import InvalidInput, strict_json


MAX_REQUEST_BYTES = 4_000_000
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
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def send_json(self, code, payload):
            body = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path != "/investigate":
                return self.send_json(404, {"error": "Unknown endpoint"})
            try:
                self.connection.settimeout(15)
                if self.headers.get("Transfer-Encoding"):
                    raise InvalidInput("Chunked requests are unsupported")
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) != 1 or not lengths[0].isdigit():
                    raise InvalidInput("Exactly one numeric Content-Length is required")
                size = int(lengths[0])
                if not 0 < size <= MAX_REQUEST_BYTES:
                    return self.send_json(413, {"error": "Request body too large or empty"})
                if self.headers.get_content_type() != "application/json":
                    return self.send_json(415, {"error": "Content-Type must be application/json"})
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise InvalidInput("Incomplete request body")
                result = investigate_request(strict_json(raw.decode("utf-8")), engine, allow_annotations)
                self.send_json(200, result)
            except (InvalidInput, ValueError, UnicodeError, TypeError) as exc:
                self.send_json(400, {"status": "invalid_input", "error": {"type": type(exc).__name__, "message": str(exc)}})
            except LLMFailure as exc:
                self.send_json(502, {"status": "extraction_failed", "claims": [], "error": {"type": type(exc).__name__, "message": str(exc), "provider_evidence": exc.evidence}})
            except Exception as exc:
                self.send_json(500, {"status": "investigation_failed", "error": {"type": type(exc).__name__, "message": str(exc)}})

        def do_GET(self):
            self.send_json(404, {"error": "Use POST /investigate"})

        def log_message(self, format, *args):
            # Access metadata only. Never log messages, raw emails or API credentials.
            return

    return ThreadingHTTPServer((host, port), Handler)
