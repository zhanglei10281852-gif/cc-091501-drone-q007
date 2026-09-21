import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from app import create_server  # noqa: E402

T0 = "2026-09-20T12:00:00Z"


def ts(seconds):
    from datetime import datetime, timedelta, timezone
    base = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ApiClient:
    def __init__(self, server):
        self.base = f"http://127.0.0.1:{server.server_port}"

    def request(self, method, path, body=None, role=None, actor=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if role:
            req.add_header("X-Role", urllib.parse.quote(role))
        if actor:
            req.add_header("X-Actor", urllib.parse.quote(actor))
        try:
            with urllib.request.urlopen(req) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def get(self, path, role=None):
        return self.request("GET", path, role=role)

    def post(self, path, body=None, role=None, actor=None):
        return self.request("POST", path, body=body, role=role, actor=actor)


class ServiceTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = str(Path(self.tmp.name) / "rid.db")
        self.server = create_server(host="127.0.0.1", port=0, db_path=self.db_path)
        self.addCleanup(self.server.storage.close)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.api = ApiClient(self.server)

    # ---------- 通用搭建 ----------

    def register_operator(self, operator_id="op-1"):
        status, body = self.api.post("/operators", {
            "operator_id": operator_id,
            "name": "航拍运营甲",
            "organization": "城市航拍有限公司",
            "contact": {"phone": "13800001111", "email": "ops@example.com"},
        })
        self.assertEqual(status, 201, body)
        return body

    def register_device(self, remote_id="RID-LEGIT-01", operator_id="op-1", device_id="dev-1"):
        status, body = self.api.post("/devices", {
            "device_id": device_id,
            "serial": f"SN-{device_id}",
            "model": "survey-x4",
            "operator_id": operator_id,
            "remote_id": remote_id,
        })
        self.assertEqual(status, 201, body)
        return body

    def add_certificate(self, device_id, valid_from, valid_to, certificate_id=None):
        payload = {"valid_from": valid_from, "valid_to": valid_to}
        if certificate_id:
            payload["certificate_id"] = certificate_id
        status, body = self.api.post(f"/devices/{device_id}/certificates", payload)
        self.assertEqual(status, 201, body)
        return body

    def register_receiver(self, receiver_id="rx-1", drift_ms=0):
        status, body = self.api.post("/receivers", {
            "receiver_id": receiver_id,
            "name": f"接收站{receiver_id}",
            "lat": 31.20, "lon": 121.50,
            "clock_drift_ms": drift_ms,
        })
        self.assertEqual(status, 201, body)
        return body

    def add_authorization(self, device_id="dev-1", operator_id="op-1"):
        status, body = self.api.post("/authorizations", {
            "operator_id": operator_id,
            "device_id": device_id,
            "purpose": "合法航拍任务",
            "lat": 31.2000, "lon": 121.5000, "radius_m": 2000,
            "start_time": "2026-09-20T11:00:00Z",
            "end_time": "2026-09-20T13:00:00Z",
        })
        self.assertEqual(status, 201, body)
        return body

    def ingest(self, receiver_id, messages):
        observations = []
        for index, message in enumerate(messages):
            observations.append({
                "message": message,
                "received_at": ts(message.get("_offset_s", index)),
            })
        status, body = self.api.post("/observations", {
            "receiver_id": receiver_id,
            "observations": observations,
        })
        self.assertEqual(status, 200, body)
        return body

    @staticmethod
    def msg(remote_id, message_id, offset_s, lat, lon, seq=None):
        message = {
            "message_id": message_id,
            "remote_id": remote_id,
            "timestamp": ts(offset_s),
            "lat": lat, "lon": lon, "alt": 120.0, "speed": 12.0, "heading": 90.0,
            "_offset_s": offset_s,
        }
        if seq is not None:
            message["seq"] = seq
        return message

    def findings(self, remote_id):
        status, body = self.api.get(f"/findings?remote_id={remote_id}")
        self.assertEqual(status, 200, body)
        return body["findings"]

    def cases(self, remote_id=None):
        path = "/cases" + (f"?remote_id={remote_id}" if remote_id else "")
        status, body = self.api.get(path)
        self.assertEqual(status, 200, body)
        return body["cases"]


class RegistrationAndIdentityViewTest(ServiceTestBase):
    def test_smooth_track_produces_no_findings(self):
        self.register_operator()
        self.register_device()
        self.add_certificate("dev-1", "2026-09-20T10:00:00Z", "2026-09-20T14:00:00Z")
        self.add_authorization()
        self.register_receiver()
        messages = [self.msg("RID-LEGIT-01", f"m-{i}", i * 10,
                             31.2000 + i * 0.0001, 121.5000, seq=i + 1) for i in range(6)]
        result = self.ingest("rx-1", messages)
        self.assertEqual(result["accepted_messages"], 6)
        self.assertEqual(result["new_findings"], [])

        status, view = self.api.get("/identities/RID-LEGIT-01", role="监管人员")
        self.assertEqual(status, 200, view)
        self.assertTrue(view["registered"])
        self.assertEqual(view["device"]["device_id"], "dev-1")
        self.assertTrue(view["identity_continuity"]["continuous"])
        self.assertEqual(view["broadcast_summary"]["message_count"], 6)
        self.assertEqual(len(view["tracklets"]), 1)
        self.assertEqual(view["tracklets"][0]["point_count"], 6)
        self.assertEqual(view["conflict_windows"], [])
        self.assertEqual(view["detections"], [])
        self.assertEqual(view["cases"], [])
        # 关联依据：设备、操作员、证书、授权、接收站均可追溯
        kinds = {a["type"] for a in view["associations"]}
        self.assertEqual(kinds, {"device", "operator", "certificate", "authorization", "receiver"})
        auth = view["authorizations"][0]
        self.assertEqual(auth["observed_points_inside"], 6)
        self.assertEqual(auth["observed_points_total"], 6)

    def test_unknown_identity_view_returns_404(self):
        status, body = self.api.get("/identities/RID-NOPE")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "identity_not_found")


class IngestIntegrityTest(ServiceTestBase):
    def setUp(self):
        super().setUp()
        self.register_operator()
        self.register_device(remote_id="RID-X", device_id="dev-x")
        self.add_certificate("dev-x", "2026-09-20T10:00:00Z", "2026-09-20T14:00:00Z")

    def test_duplicate_messages_do_not_create_false_track(self):
        self.register_receiver()
        messages = [self.msg("RID-X", f"m-{i}", i * 10, 31.2 + i * 0.0001, 121.5) for i in range(4)]
        first = self.ingest("rx-1", messages)
        self.assertEqual(first["accepted_messages"], 4)
        second = self.ingest("rx-1", messages)
        self.assertEqual(second["accepted_messages"], 0)
        self.assertEqual(second["duplicate_messages"], 4)
        status, view = self.api.get("/identities/RID-X")
        self.assertEqual(view["broadcast_summary"]["message_count"], 4)
        self.assertEqual(len(view["tracklets"]), 1)

    def test_same_broadcast_seen_by_two_receivers_is_one_message(self):
        self.register_receiver("rx-1")
        self.register_receiver("rx-2")
        message = self.msg("RID-X", "m-1", 0, 31.2, 121.5)
        self.ingest("rx-1", [message])
        result = self.ingest("rx-2", [message])
        self.assertEqual(result["accepted_messages"], 0)
        self.assertEqual(result["duplicate_messages"], 1)
        self.assertEqual(result["observations_linked"], 1)
        status, view = self.api.get("/identities/RID-X")
        self.assertEqual(view["broadcast_summary"]["message_count"], 1)
        self.assertEqual(len(view["broadcast_summary"]["receivers"]), 2)

    def test_out_of_order_messages_same_result_as_ordered(self):
        self.register_receiver()
        ordered = [self.msg("RID-X", f"m-{i}", i * 10, 31.2 + i * 0.0001, 121.5) for i in range(6)]
        shuffled = [ordered[i] for i in (3, 0, 5, 1, 4, 2)]
        result = self.ingest("rx-1", shuffled)
        self.assertEqual(result["accepted_messages"], 6)
        self.assertEqual(result["new_findings"], [])
        status, view = self.api.get("/identities/RID-X")
        self.assertEqual(len(view["tracklets"]), 1)
        self.assertEqual(view["tracklets"][0]["point_count"], 6)
        self.assertEqual(view["tracklets"][0]["start"], ts(0))
        self.assertEqual(view["tracklets"][0]["end"], ts(50))
        self.assertEqual(view["detections"], [])


class DuplicateIdentityScenarioTest(ServiceTestBase):
    """监管席一分钟内看到两个相距十公里的目标广播同一 Remote ID。"""

    def _ingest_scenario(self, receiver_id="rx-1"):
        messages = []
        for i in range(6):
            offset = i * 10
            messages.append(self.msg("RID-LEGIT-01", f"legit-{i}", offset, 31.2000, 121.5000, seq=i + 1))
            messages.append(self.msg("RID-LEGIT-01", f"spoof-{i}", offset, 31.2900, 121.5000, seq=i + 1))
        return self.ingest(receiver_id, messages)

    def test_conflict_detected_and_case_created(self):
        self.register_operator()
        self.register_device()
        self.add_certificate("dev-1", "2026-09-20T10:00:00Z", "2026-09-20T14:00:00Z")
        self.add_authorization()
        self.register_receiver()
        result = self._ingest_scenario()
        self.assertTrue(result["new_findings"])

        findings = self.findings("RID-LEGIT-01")
        rules = {f["rule_id"] for f in findings}
        self.assertIn("duplicate_identity", rules)
        duplicate = next(f for f in findings if f["rule_id"] == "duplicate_identity")
        self.assertGreaterEqual(duplicate["details"]["max_separation_m"], 9000)
        self.assertEqual(duplicate["window_start"], ts(0))
        self.assertEqual(duplicate["window_end"], ts(50))

        cases = self.cases("RID-LEGIT-01")
        self.assertTrue(any(c["rule_id"] == "duplicate_identity" for c in cases))
        duplicate_case = next(c for c in cases if c["rule_id"] == "duplicate_identity")
        self.assertEqual(duplicate_case["severity"], "high")
        self.assertEqual(duplicate_case["status"], "open")
        self.assertFalse(duplicate_case["overdue"])

        status, view = self.api.get("/identities/RID-LEGIT-01", role="监管人员")
        self.assertEqual(status, 200, view)
        # 冲突发生在哪段时间
        self.assertEqual(len(view["conflict_windows"]), 1)
        window = view["conflict_windows"][0]
        self.assertEqual(window["start"], ts(0))
        self.assertEqual(window["end"], ts(50))
        self.assertIn("duplicate_identity", window["rule_ids"])
        # 采用的检测规则
        self.assertIn("duplicate_identity", {d["rule_id"] for d in view["detections"]})
        # 当前处置进展
        case_view = next(c for c in view["cases"] if c["rule_id"] == "duplicate_identity")
        self.assertEqual(case_view["status"], "open")
        self.assertTrue(any(e["kind"] == "detection" for e in case_view["progress"]))
        # 合法航拍任务的授权关联仍在
        self.assertEqual(view["authorizations"][0]["observed_points_inside"], 6)

    def test_detection_is_idempotent_on_rescan(self):
        self.register_receiver()
        self._ingest_scenario()
        before = self.findings("RID-LEGIT-01")
        status, body = self.api.post("/detections/run", {"remote_id": "RID-LEGIT-01"})
        self.assertEqual(status, 200)
        self.assertEqual(body["new_findings"], [])
        after = self.findings("RID-LEGIT-01")
        self.assertEqual(len(before), len(after))
        self.assertEqual(len(self.cases("RID-LEGIT-01")), len({f["rule_id"] for f in before}))


class KinematicRuleTest(ServiceTestBase):
    def setUp(self):
        super().setUp()
        self.register_receiver()

    def test_impossible_speed(self):
        messages = [
            self.msg("RID-S", "m-1", 0, 31.2000, 121.5000),
            self.msg("RID-S", "m-2", 10, 31.2540, 121.5000),  # 约6km/10s ≈ 600m/s
        ]
        self.ingest("rx-1", messages)
        findings = self.findings("RID-S")
        speed = next(f for f in findings if f["rule_id"] == "impossible_speed")
        self.assertGreater(speed["details"]["implied_speed_mps"], 75)
        self.assertEqual(speed["window_start"], ts(0))
        self.assertEqual(speed["window_end"], ts(10))

    def test_position_jump(self):
        messages = [
            self.msg("RID-J", "m-1", 0, 31.2000, 121.5000),
            self.msg("RID-J", "m-2", 1, 31.2180, 121.5000),  # 约2km/1s：瞬时跳变
        ]
        self.ingest("rx-1", messages)
        findings = self.findings("RID-J")
        jump = next(f for f in findings if f["rule_id"] == "position_jump")
        self.assertEqual(jump["details"]["dt_s"], 1)
        self.assertGreaterEqual(jump["details"]["distance_m"], 1500)
        self.assertFalse(any(f["rule_id"] == "impossible_speed" for f in findings))


class CertificateRuleTest(ServiceTestBase):
    def setUp(self):
        super().setUp()
        self.register_operator()
        self.register_device()
        self.register_receiver()

    def test_expired_certificate_detected(self):
        self.add_certificate("dev-1", "2026-09-20T10:00:00Z", "2026-09-20T11:00:00Z")
        ok_msg = self.msg("RID-LEGIT-01", "m-ok", -3600, 31.2, 121.5)  # 11:00 边界内? 12:00-3600=11:00
        late = [self.msg("RID-LEGIT-01", f"m-late-{i}", 600 + i * 10, 31.2 + i * 0.0001, 121.5) for i in range(3)]
        self.ingest("rx-1", [ok_msg] + late)
        findings = self.findings("RID-LEGIT-01")
        expired = next(f for f in findings if f["rule_id"] == "expired_certificate")
        self.assertEqual(expired["details"]["message_count"], 3)
        self.assertEqual(expired["window_start"], ts(600))

    def test_certificate_rotation_keeps_identity_continuous(self):
        self.add_certificate("dev-1", "2026-09-20T10:00:00Z", "2026-09-20T12:00:00Z", "cert-a")
        self.add_certificate("dev-1", "2026-09-20T12:00:00Z", "2026-09-20T14:00:00Z", "cert-b")
        messages = [
            self.msg("RID-LEGIT-01", "m-before", -600, 31.2, 121.5),   # 旧证书时段
            self.msg("RID-LEGIT-01", "m-after", 600, 31.2001, 121.5),   # 轮换后新证书时段
        ]
        result = self.ingest("rx-1", messages)
        self.assertEqual(result["new_findings"], [])
        status, view = self.api.get("/identities/RID-LEGIT-01")
        self.assertTrue(view["identity_continuity"]["continuous"])
        self.assertEqual(len(view["identity_continuity"]["certificate_windows"]), 2)

    def test_unregistered_identity_flagged(self):
        self.ingest("rx-1", [self.msg("RID-GHOST", "m-1", 0, 31.2, 121.5)])
        findings = self.findings("RID-GHOST")
        self.assertEqual([f["rule_id"] for f in findings], ["unregistered_identity"])
        cases = self.cases("RID-GHOST")
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["rule_id"], "unregistered_identity")


class ClockDriftTest(ServiceTestBase):
    def _scenario_messages(self, remote_id):
        return [
            self.msg(remote_id, "a-1", 0, 31.2000, 121.5000),
            self.msg(remote_id, "b-1", 10, 31.2900, 121.5000),
            self.msg(remote_id, "a-2", 20, 31.2000, 121.5000),
            self.msg(remote_id, "b-2", 30, 31.2900, 121.5000),
        ]

    def _confidence_with_drift(self, drift_ms):
        remote_id = f"RID-DRIFT-{drift_ms}"
        receiver_id = f"rx-drift-{drift_ms}"
        self.register_receiver(receiver_id, drift_ms=drift_ms)
        self.ingest(receiver_id, self._scenario_messages(remote_id))
        findings = self.findings(remote_id)
        return next(f for f in findings if f["rule_id"] == "duplicate_identity")

    def test_clock_drift_only_lowers_confidence(self):
        clean = self._confidence_with_drift(0)
        drifted = self._confidence_with_drift(5000)
        self.assertLess(drifted["confidence"], clean["confidence"])
        self.assertTrue(any("时钟漂移" in factor for factor in drifted["confidence_factors"]))
        self.assertTrue(any("不直接构成定性" in factor for factor in drifted["confidence_factors"]))
        # 漂移不阻断案件进入人工复核，也不自动定性
        cases = self.cases("RID-DRIFT-5000")
        self.assertTrue(cases)
        self.assertTrue(all(c["status"] == "open" for c in cases))


class CaseWorkflowTest(ServiceTestBase):
    def setUp(self):
        super().setUp()
        self.register_receiver()
        messages = []
        for i in range(4):
            offset = i * 10
            messages.append(self.msg("RID-C", f"a-{i}", offset, 31.2000, 121.5000))
            messages.append(self.msg("RID-C", f"b-{i}", offset, 31.2900, 121.5000))
        self.ingest("rx-1", messages)

    def _case_of_rule(self, rule_id):
        return next(c for c in self.cases("RID-C") if c["rule_id"] == rule_id)

    def test_disposition_via_appended_evidence(self):
        case = self._case_of_rule("duplicate_identity")
        case_id = case["case_id"]
        original_due = case["review_due_at"]

        status, body = self.api.post(f"/cases/{case_id}/events",
                                     {"kind": "comment", "payload": {"text": "已联系空域管理部门"}},
                                     role="调查员", actor="调查员-01")
        self.assertEqual(status, 201, body)
        self.assertEqual(body["case"]["status"], "open")

        status, body = self.api.post(f"/cases/{case_id}/events", {"kind": "review", "payload": {}})
        self.assertEqual(status, 201)
        self.assertEqual(body["case"]["status"], "under_review")

        status, body = self.api.post(f"/cases/{case_id}/events",
                                     {"kind": "escalate", "payload": {"reason": "疑似冒用身份"}})
        self.assertEqual(status, 201)
        escalated = body["case"]
        self.assertEqual(escalated["status"], "escalated")
        self.assertEqual(escalated["severity"], "critical")  # high 再升一级
        self.assertLess(escalated["review_due_at"], original_due)

        status, body = self.api.post(f"/cases/{case_id}/events",
                                     {"kind": "exclude", "payload": {"reason": "确认为测试信号"}})
        self.assertEqual(status, 201)
        self.assertEqual(body["case"]["status"], "excluded")

        status, body = self.api.post(f"/cases/{case_id}/events",
                                     {"kind": "reopen", "payload": {"reason": "复核结论被推翻"}})
        self.assertEqual(status, 201)
        self.assertEqual(body["case"]["status"], "under_review")

        status, body = self.api.post(f"/cases/{case_id}/events",
                                     {"kind": "resolve", "payload": {"resolution": "已处置"}})
        self.assertEqual(status, 201)
        final = body["case"]
        self.assertEqual(final["status"], "resolved")
        kinds = [e["kind"] for e in final["progress"]]
        self.assertEqual(kinds, ["detection", "comment", "review", "escalate", "exclude", "reopen", "resolve"])
        self.assertEqual(final["progress"][1]["actor"], "调查员-01")

    def test_merge_cases_by_appending_evidence(self):
        duplicate_case = self._case_of_rule("duplicate_identity")
        speed_case = self._case_of_rule("impossible_speed")
        status, body = self.api.post(
            f"/cases/{duplicate_case['case_id']}/events",
            {"kind": "merge", "payload": {"absorb_case_id": speed_case["case_id"], "reason": "同一冲突"}},
            role="调查员")
        self.assertEqual(status, 201, body)

        status, absorbed = self.api.get(f"/cases/{speed_case['case_id']}")
        self.assertEqual(absorbed["status"], "merged")
        self.assertEqual(absorbed["merged_into"], duplicate_case["case_id"])
        self.assertTrue(any(e["kind"] == "merged_into" for e in absorbed["progress"]))

        status, primary = self.api.get(f"/cases/{duplicate_case['case_id']}")
        self.assertTrue(any(e["kind"] == "merge" for e in primary["progress"]))
        rules = {f["rule_id"] for f in primary["findings"]}
        self.assertEqual(rules, {"duplicate_identity", "impossible_speed"})

        # 已合并案件不可再处置
        status, body = self.api.post(f"/cases/{speed_case['case_id']}/events",
                                     {"kind": "comment", "payload": {"text": "x"}})
        self.assertEqual(status, 409)

    def test_exclude_requires_reason(self):
        case = self._case_of_rule("duplicate_identity")
        status, body = self.api.post(f"/cases/{case['case_id']}/events",
                                     {"kind": "exclude", "payload": {}})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "reason_required")


class PiiMaskingTest(ServiceTestBase):
    def test_contact_visible_only_to_investigator(self):
        self.register_operator()
        status, masked = self.api.get("/operators/op-1", role="监管人员")
        self.assertEqual(status, 200)
        self.assertEqual(masked["contact"], {"phone": "***", "email": "***"})
        self.assertTrue(masked["contact_masked"])

        status, masked = self.api.get("/operators/op-1")
        self.assertEqual(masked["contact"]["phone"], "***")

        status, visible = self.api.get("/operators/op-1", role="调查员")
        self.assertEqual(visible["contact"], {"phone": "13800001111", "email": "ops@example.com"})
        self.assertFalse(visible["contact_masked"])

        # 身份视图中的操作员同样脱敏
        self.register_device()
        self.register_receiver()
        self.ingest("rx-1", [self.msg("RID-LEGIT-01", "m-1", 0, 31.2, 121.5)])
        status, view = self.api.get("/identities/RID-LEGIT-01", role="监管人员")
        self.assertEqual(view["operator"]["contact"]["phone"], "***")
        status, view = self.api.get("/identities/RID-LEGIT-01", role="调查员")
        self.assertEqual(view["operator"]["contact"]["phone"], "13800001111")


class PersistenceTest(ServiceTestBase):
    def test_open_cases_and_deadlines_survive_restart(self):
        self.register_receiver()
        messages = []
        for i in range(4):
            offset = i * 10
            messages.append(self.msg("RID-P", f"a-{i}", offset, 31.2000, 121.5000))
            messages.append(self.msg("RID-P", f"b-{i}", offset, 31.2900, 121.5000))
        self.ingest("rx-1", messages)
        before = self.cases("RID-P")
        self.assertTrue(before)
        due_map = {c["case_id"]: c["review_due_at"] for c in before}

        # 模拟服务重启：关闭当前存储，在同一数据库上重建服务
        self.server.shutdown()
        self.server.server_close()
        self.server.storage.close()
        restarted = create_server(host="127.0.0.1", port=0, db_path=self.db_path)
        self.addCleanup(restarted.storage.close)
        self.addCleanup(restarted.server_close)
        self.addCleanup(restarted.shutdown)
        threading.Thread(target=restarted.serve_forever, daemon=True).start()
        api = ApiClient(restarted)

        status, body = api.get("/cases?remote_id=RID-P")
        self.assertEqual(status, 200)
        after = body["cases"]
        self.assertEqual({c["case_id"] for c in after}, set(due_map))
        for case in after:
            self.assertEqual(case["review_due_at"], due_map[case["case_id"]])
            self.assertEqual(case["status"], "open")
            self.assertIsNotNone(case["remaining_seconds"])

        status, view = api.get("/identities/RID-P", role="监管人员")
        self.assertEqual(status, 200)
        self.assertEqual(len(view["conflict_windows"]), 1)
        self.assertTrue(view["cases"])


if __name__ == "__main__":
    unittest.main()
