"""HTTP 接口层：路由、角色解析、统一错误响应。"""
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from rid.models import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    Role,
    ValidationError,
)
from rid.service import RidService

SERVICE_NAME = "remote-id-oversight-service"


def _default_db_path():
    return os.path.join(os.environ.get("DATA_DIR", ".data"), "rid.db")


class Handler(BaseHTTPRequestHandler):
    server_version = "RidOversight/1.0"

    # ---- 基础设施 ----

    @property
    def service(self) -> RidService:
        return self.server.service  # type: ignore[attr-defined]

    def _send_json(self, status: int, obj) -> None:
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValidationError("请求体必须是合法 JSON") from exc

    def _role(self) -> Role:
        raw = self.headers.get("X-Actor-Role", Role.READONLY.value)
        try:
            return Role(raw)
        except ValueError as exc:
            raise ValidationError(f"未知角色: {raw!r}") from exc

    def _actor(self) -> str:
        return self.headers.get("X-Actor-Id", "anonymous")

    def log_message(self, *_args):
        return

    # ---- 路由 ----

    def do_GET(self):  # noqa: N802
        self._dispatch("GET")

    def do_POST(self):  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str):
        path = self.path.split("?", 1)[0]
        try:
            self._role()  # 每个请求都校验角色头合法性
            handler, groups = self._match(method, path)
            if handler is None:
                self._send_json(404, {"error": "not_found"})
                return
            result = handler(*groups)
            if result is not None:
                status, body = result
                self._send_json(status, body)
        except ValidationError as exc:
            self._send_json(400, {"error": "validation_error", "message": str(exc)})
        except ForbiddenError as exc:
            self._send_json(403, {"error": "forbidden", "message": str(exc)})
        except NotFoundError as exc:
            self._send_json(404, {"error": "not_found", "message": str(exc)})
        except ConflictError as exc:
            self._send_json(409, {"error": "conflict", "message": str(exc)})

    def _match(self, method: str, path: str):
        routes = {
            ("GET", re.compile(r"^/health$")): self._health,
            ("POST", re.compile(r"^/v1/operators$")): self._post_operator,
            ("POST", re.compile(r"^/v1/devices$")): self._post_device,
            ("POST", re.compile(r"^/v1/devices/([^/]+)/certificates$")): self._post_certificate,
            ("POST", re.compile(r"^/v1/authorizations$")): self._post_authorization,
            ("POST", re.compile(r"^/v1/receivers$")): self._post_receiver,
            ("POST", re.compile(r"^/v1/observations$")): self._post_observations,
            ("GET", re.compile(r"^/v1/remote-ids/([^/]+)$")): self._get_remote_id,
            ("GET", re.compile(r"^/v1/cases$")): self._get_cases,
            ("GET", re.compile(r"^/v1/cases/([^/]+)$")): self._get_case,
            ("POST", re.compile(r"^/v1/cases/([^/]+)/evidence$")): self._post_evidence,
            ("POST", re.compile(r"^/v1/cases/([^/]+)/dispositions$")): self._post_disposition,
        }
        for (route_method, pattern), handler in routes.items():
            if route_method != method:
                continue
            match = pattern.match(path)
            if match:
                return handler, match.groups()
        return None, ()

    # ---- 端点 ----

    def _health(self):
        return 200, {"status": "ok", "service": SERVICE_NAME}

    def _post_operator(self):
        return 200, self.service.register_operator(self._read_json(), self._role())

    def _post_device(self):
        return 200, self.service.register_device(self._read_json(), self._role())

    def _post_certificate(self, device_id: str):
        return 200, self.service.add_certificate(device_id, self._read_json(), self._role())

    def _post_authorization(self):
        return 200, self.service.create_authorization(self._read_json(), self._role())

    def _post_receiver(self):
        return 200, self.service.register_receiver(self._read_json(), self._role())

    def _post_observations(self):
        body = self._read_json()
        items = body.get("observations") if isinstance(body, dict) else body
        return 200, self.service.ingest_observations(items, self._role(), self._actor())

    def _get_remote_id(self, remote_id: str):
        return 200, self.service.remote_id_view(remote_id, self._role())

    def _get_cases(self):
        from urllib.parse import parse_qs, urlsplit

        query = parse_qs(urlsplit(self.path).query)
        status = query.get("status", [None])[0]
        overdue = query.get("overdue", ["false"])[0].lower() == "true"
        return 200, {"cases": self.service.list_cases(status=status, overdue=overdue)}

    def _get_case(self, case_id: str):
        return 200, self.service.case_view(case_id, self._role())

    def _post_evidence(self, case_id: str):
        return 200, self.service.append_evidence(
            case_id, self._read_json(), self._role(), self._actor()
        )

    def _post_disposition(self, case_id: str):
        return 200, self.service.dispose(
            case_id, self._read_json(), self._role(), self._actor()
        )


def create_server(host=None, port=None, db_path=None):
    host = host or os.environ.get("HOST", "0.0.0.0")
    port = int(port if port is not None else os.environ.get("PORT", "8000"))
    db_path = db_path or _default_db_path()
    server = ThreadingHTTPServer((host, port), Handler)
    server.service = RidService(db_path)  # type: ignore[attr-defined]
    return server
