import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from app import create_server  # noqa: E402

BASE = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


def ts(seconds):
    return (BASE + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.server = create_server(
            host="127.0.0.1", port=0, db_path=str(Path(cls.tmp.name) / "rid.db")
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server.service.close()
        cls.tmp.cleanup()

    def call(self, method, path, body=None, role=None, actor=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.url + path, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if role:
            request.add_header("X-Actor-Role", role)
        if actor:
            request.add_header("X-Actor-Id", actor)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_full_oversight_flow(self):
        # 未带角色头默认为只读：不能登记
        status, body = self.call("POST", "/v1/operators", {"name": "某公司"})
        self.assertEqual(status, 403)

        status, _ = self.call(
            "POST", "/v1/operators",
            {"operator_id": "op-1", "name": "某公司", "phone": "13800001111"},
            role="regulator",
        )
        self.assertEqual(status, 200)
        self.call(
            "POST", "/v1/devices",
            {"device_id": "dev-1", "operator_id": "op-1", "serial_number": "SN-1"},
            role="regulator",
        )
        self.call(
            "POST", "/v1/devices/dev-1/certificates",
            {"cert_id": "cert-1", "remote_id": "RID-HTTP",
             "valid_from": ts(-7200), "valid_to": ts(7200)},
            role="regulator",
        )
        for rx, lon in (("st-1", 121.0), ("st-2", 121.1)):
            self.call(
                "POST", "/v1/receivers",
                {"receiver_id": rx, "lat": 31.0, "lon": lon,
                 "clock_uncertainty_ms": 50},
                role="regulator",
            )

        batch = []
        for i in range(3):
            batch.append({"remote_id": "RID-HTTP", "seq": i, "device_time": ts(i * 20),
                          "lat": 31.0 + i * 0.0001, "lon": 121.0, "receiver_id": "st-1",
                          "received_at": ts(i * 20 + 1), "cert_id": "cert-1"})
            batch.append({"remote_id": "RID-HTTP", "seq": i, "device_time": ts(i * 20 + 5),
                          "lat": 31.0 + i * 0.0001, "lon": 121.1, "receiver_id": "st-2",
                          "received_at": ts(i * 20 + 6), "cert_id": "cert-1"})
        status, body = self.call(
            "POST", "/v1/observations", {"observations": batch}, role="system"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(body["accepted"]), 6)
        self.assertEqual(len(body["cases"]), 1)
        case_id = body["cases"][0]["case_id"]

        # 监管人员检索：看到冲突时段、规则与进展，但联系方式脱敏
        status, view = self.call("GET", "/v1/remote-ids/RID-HTTP", role="regulator")
        self.assertEqual(status, 200)
        self.assertEqual(view["conflict_windows"][0]["rules"], ["duplicate_identity"])
        self.assertEqual(view["cases"][0]["case_id"], case_id)
        self.assertTrue(view["registration"]["operators"][0]["contact_redacted"])

        # 调查员可见联系方式与完整证据链
        status, view = self.call("GET", "/v1/remote-ids/RID-HTTP", role="investigator")
        self.assertEqual(
            view["registration"]["operators"][0]["phone"], "13800001111"
        )
        status, case = self.call("GET", f"/v1/cases/{case_id}", role="investigator")
        self.assertEqual(case["findings"][0]["rule"], "duplicate_identity")
        self.assertEqual(case["findings"][0]["rule_version"], "1.0")

        # 监管人员不能处置案件
        status, _ = self.call(
            "POST", f"/v1/cases/{case_id}/dispositions",
            {"action": "escalate"}, role="regulator",
        )
        self.assertEqual(status, 403)
        # 调查员处置
        status, case = self.call(
            "POST", f"/v1/cases/{case_id}/dispositions",
            {"action": "escalate", "reason": "涉及人口密集区"},
            role="investigator", actor="inv-1",
        )
        self.assertEqual(status, 200)
        self.assertEqual(case["status"], "ESCALATED")
        self.assertEqual(case["timeline"][-1]["actor"], "inv-1")

    def test_unknown_role_rejected(self):
        status, body = self.call("GET", "/v1/cases", role="admin")
        self.assertEqual(status, 400)

    def test_unknown_path_is_404(self):
        status, _ = self.call("GET", "/v1/nope")
        self.assertEqual(status, 404)

    def test_case_not_found_is_404(self):
        status, _ = self.call("GET", "/v1/cases/case-missing", role="regulator")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
