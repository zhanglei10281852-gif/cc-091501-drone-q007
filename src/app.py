import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from rid.config import DEFAULT_ROLE
from rid.service import Service, ServiceError
from rid.storage import Storage, default_db_path


SERVICE_NAME = "drone-management-starter"


def _ok(service, _match, _body, _role, _actor, _query):
    return 200, {"status": "ok", "service": SERVICE_NAME}


def _create_operator(service, _match, body, _role, _actor, _query):
    return 201, service.create_operator(_require_body(body))


def _list_operators(service, _match, _body, role, _actor, _query):
    return 200, {"operators": service.list_operators(role)}


def _get_operator(service, match, _body, role, _actor, _query):
    return 200, service.get_operator(match.group("id"), role)


def _create_device(service, _match, body, _role, _actor, _query):
    return 201, service.create_device(_require_body(body))


def _get_device(service, match, _body, _role, _actor, _query):
    return 200, service.get_device(match.group("id"))


def _add_certificate(service, match, body, _role, _actor, _query):
    return 201, service.add_certificate(match.group("id"), _require_body(body))


def _create_authorization(service, _match, body, _role, _actor, _query):
    return 201, service.create_authorization(_require_body(body))


def _get_authorization(service, match, _body, _role, _actor, _query):
    return 200, service.get_authorization(match.group("id"))


def _create_receiver(service, _match, body, _role, _actor, _query):
    return 201, service.create_receiver(_require_body(body))


def _list_receivers(service, _match, _body, _role, _actor, _query):
    return 200, {"receivers": service.list_receivers()}


def _ingest(service, _match, body, _role, _actor, _query):
    return 200, service.ingest_observations(_require_body(body))


def _run_detection(service, _match, body, _role, _actor, _query):
    body = body or {}
    return 200, service.run_detection(body.get("remote_id"))


def _list_identities(service, _match, _body, _role, _actor, _query):
    return 200, {"identities": service.list_identities()}


def _identity_view(service, match, _body, role, _actor, _query):
    return 200, service.identity_view(match.group("remote_id"), role)


def _list_findings(service, _match, _body, _role, _actor, query):
    remote_id = _query_one(query, "remote_id")
    return 200, {"findings": service.list_findings(remote_id)}


def _list_cases(service, _match, _body, _role, _actor, query):
    overdue = _query_one(query, "overdue")
    return 200, {"cases": service.list_cases(
        status=_query_one(query, "status"),
        remote_id=_query_one(query, "remote_id"),
        overdue=True if overdue == "true" else None)}


def _get_case(service, match, _body, _role, _actor, _query):
    return 200, service.get_case(match.group("id"))


def _append_case_event(service, match, body, _role, actor, _query):
    body = _require_body(body)
    kind = body.get("kind")
    if not kind:
        raise ServiceError(400, "missing_field", "缺少必填字段: kind")
    return 201, service.append_case_event(match.group("id"), kind, body.get("payload") or {}, actor)


def _require_body(body):
    if not isinstance(body, dict):
        raise ServiceError(400, "invalid_body", "请求体必须为 JSON 对象")
    return body


def _query_one(query, key):
    values = query.get(key)
    return values[0] if values else None


ROUTES = [
    ("GET", re.compile(r"^/health$"), _ok),
    ("POST", re.compile(r"^/operators$"), _create_operator),
    ("GET", re.compile(r"^/operators$"), _list_operators),
    ("GET", re.compile(r"^/operators/(?P<id>[^/]+)$"), _get_operator),
    ("POST", re.compile(r"^/devices$"), _create_device),
    ("GET", re.compile(r"^/devices/(?P<id>[^/]+)$"), _get_device),
    ("POST", re.compile(r"^/devices/(?P<id>[^/]+)/certificates$"), _add_certificate),
    ("POST", re.compile(r"^/authorizations$"), _create_authorization),
    ("GET", re.compile(r"^/authorizations/(?P<id>[^/]+)$"), _get_authorization),
    ("POST", re.compile(r"^/receivers$"), _create_receiver),
    ("GET", re.compile(r"^/receivers$"), _list_receivers),
    ("POST", re.compile(r"^/observations$"), _ingest),
    ("POST", re.compile(r"^/detections/run$"), _run_detection),
    ("GET", re.compile(r"^/identities$"), _list_identities),
    ("GET", re.compile(r"^/identities/(?P<remote_id>[^/]+)$"), _identity_view),
    ("GET", re.compile(r"^/findings$"), _list_findings),
    ("GET", re.compile(r"^/cases$"), _list_cases),
    ("GET", re.compile(r"^/cases/(?P<id>[^/]+)$"), _get_case),
    ("POST", re.compile(r"^/cases/(?P<id>[^/]+)/events$"), _append_case_event),
]


def _make_handler(service):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self._dispatch("GET")

        def do_POST(self):  # noqa: N802
            self._dispatch("POST")

        def _dispatch(self, method):
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            # 角色名含中文，头部按 percent-encoding 传输；也接受查询参数 role
            role = unquote(self.headers.get("X-Role") or "") or _query_one(query, "role") or DEFAULT_ROLE
            actor = unquote(self.headers.get("X-Actor") or "") or role
            body = None
            if method == "POST":
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                if raw:
                    try:
                        body = json.loads(raw.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        self._respond(400, {"error": "invalid_json", "message": "请求体不是合法 JSON"})
                        return
            for route_method, pattern, handler in ROUTES:
                if route_method != method:
                    continue
                match = pattern.match(parsed.path)
                if not match:
                    continue
                try:
                    status, payload = handler(service, match, body, role, actor, query)
                except ServiceError as exc:
                    self._respond(exc.status, {"error": exc.code, "message": exc.message})
                except Exception as exc:  # noqa: BLE001
                    self._respond(500, {"error": "internal_error", "message": str(exc)})
                else:
                    self._respond(status, payload)
                return
            self._respond(404, {"error": "not_found"})

        def _respond(self, status, payload):
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            return

    return Handler


def create_server(host=None, port=None, db_path=None):
    storage = Storage(db_path or default_db_path())
    service = Service(storage)
    server = ThreadingHTTPServer(
        (host or os.environ.get("HOST", "0.0.0.0"),
         int(port or os.environ.get("PORT", "8000"))),
        _make_handler(service),
    )
    server.daemon_threads = True
    server.storage = storage
    server.service = service
    return server
