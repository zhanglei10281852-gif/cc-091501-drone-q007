import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from rid.models import ConflictError, Role  # noqa: E402
from rid.service import RidService  # noqa: E402

BASE = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
REG = Role.REGULATOR
INV = Role.INVESTIGATOR
SYS = Role.SYSTEM


def ts(seconds):
    return (BASE + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def obs(remote_id, seq, t_s, lat, lon, receiver, cert=None):
    return {
        "remote_id": remote_id,
        "seq": seq,
        "device_time": ts(t_s),
        "lat": lat,
        "lon": lon,
        "receiver_id": receiver,
        "received_at": ts(t_s + 1),
        "cert_id": cert,
    }


class ServiceTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "rid.db")
        self.svc = self._open_service()
        self.addCleanup(self.svc.close)

    def _open_service(self, **kwargs):
        return RidService(self.db, **kwargs)

    def register_site(self, clock_uncertainty_ms=50.0):
        self.svc.register_operator(
            {
                "operator_id": "op-1",
                "name": "合法航拍公司",
                "phone": "13800001111",
                "email": "ops@example.com",
                "id_number": "ID-9",
            },
            REG,
        )
        self.svc.register_device(
            {"device_id": "dev-1", "operator_id": "op-1", "serial_number": "SN-1"},
            REG,
        )
        self.svc.add_certificate(
            "dev-1",
            {
                "cert_id": "cert-1",
                "remote_id": "RID-X",
                "valid_from": ts(-7200),
                "valid_to": ts(7200),
            },
            REG,
        )
        self.svc.create_authorization(
            {
                "auth_id": "auth-1",
                "device_id": "dev-1",
                "area": {"type": "circle", "center": [31.0, 121.0], "radius_m": 3000},
                "start_time": ts(-3600),
                "end_time": ts(3600),
            },
            REG,
        )
        self.svc.register_receiver(
            {"receiver_id": "st-1", "lat": 31.0, "lon": 121.0,
             "clock_uncertainty_ms": clock_uncertainty_ms},
            REG,
        )
        self.svc.register_receiver(
            {"receiver_id": "st-2", "lat": 31.0, "lon": 121.1,
             "clock_uncertainty_ms": clock_uncertainty_ms},
            REG,
        )

    def ingest_duplicate_scene(self, remote_id="RID-X", t0=0, cert="cert-1"):
        """两个相距约 10 公里的目标在同一分钟广播同一编号。"""
        batch = []
        for i in range(3):
            batch.append(obs(remote_id, i, t0 + i * 20, 31.0 + i * 0.0001, 121.0, "st-1", cert))
            batch.append(obs(remote_id, i, t0 + i * 20 + 5, 31.0 + i * 0.0001, 121.1, "st-2", cert))
        return self.svc.ingest_observations(batch, SYS)


class DuplicateIdentityTest(ServiceTestBase):
    def test_two_sources_same_remote_id_open_review_case(self):
        self.register_site()
        result = self.ingest_duplicate_scene()
        self.assertEqual(len(result["rejected"]), 0)
        self.assertEqual(len(result["accepted"]), 6)
        dup_cases = [c for c in result["cases"] if c["rule"] == "duplicate_identity"]
        self.assertEqual(len(dup_cases), 1)
        case_id = dup_cases[0]["case_id"]

        view = self.svc.case_view(case_id, INV)
        self.assertEqual(view["status"], "OPEN")
        self.assertEqual(view["severity"], "high")
        self.assertIn("duplicate_identity", view["rules"])
        dup_finding = next(
            f for f in view["findings"] if f["rule"] == "duplicate_identity"
        )
        self.assertEqual(dup_finding["confidence"], 1.0)
        self.assertEqual(dup_finding["details"]["cluster_count"], 2)
        self.assertGreater(dup_finding["details"]["max_separation_m"], 5000)
        # 冲突时间窗覆盖两个簇的重叠时段
        self.assertEqual(dup_finding["window_start"], ts(0))
        self.assertEqual(dup_finding["window_end"], ts(45))

        remote_view = self.svc.remote_id_view("RID-X", REG)
        windows = remote_view["conflict_windows"]
        self.assertTrue(windows)
        self.assertIn("duplicate_identity", windows[0]["rules"])
        self.assertEqual(windows[0]["start"], ts(0))
        self.assertEqual(windows[0]["end"], ts(45))
        # 登记关联：设备、操作员、证书链、授权齐全
        registration = remote_view["registration"]
        self.assertEqual(registration["devices"][0]["device_id"], "dev-1")
        self.assertEqual(len(registration["certificate_chain"]), 1)
        self.assertEqual(len(registration["authorizations"]), 1)

    def test_new_evidence_merges_into_existing_case(self):
        self.register_site()
        self.ingest_duplicate_scene(t0=0)
        # 5 分钟后同一身份再次冲突：归入同一案件而不是开新案
        self.ingest_duplicate_scene(t0=300)
        cases = self.svc.list_cases()
        self.assertEqual(len(cases), 1)
        view = self.svc.case_view(cases[0]["case_id"], INV)
        dup_findings = [f for f in view["findings"] if f["rule"] == "duplicate_identity"]
        self.assertEqual(len(dup_findings), 2)
        # 冲突时间窗随证据追加而扩展
        remote_view = self.svc.remote_id_view("RID-X", REG)
        self.assertEqual(remote_view["conflict_windows"][0]["end"], ts(345))


class TrackIntegrityTest(ServiceTestBase):
    def test_out_of_order_and_duplicate_reports_make_no_false_track(self):
        self.register_site()
        # 正常单目标轨迹：每秒约 15 米，乱序 + 重复上报
        points = [
            obs("RID-X", i, i * 20, 31.0 + i * 0.00135, 121.0, "st-1", "cert-1")
            for i in range(8)
        ]
        shuffled = points[::-1] + points[:3]  # 逆序到达且前 3 条重复
        result = self.svc.ingest_observations(shuffled, SYS)
        self.assertEqual(len(result["accepted"]), 8)
        self.assertEqual(len(result["duplicates"]), 3)
        self.assertEqual(result["cases"], [])
        view = self.svc.remote_id_view("RID-X", REG)
        self.assertEqual(view["cases"], [])
        track = view["recent_track"]
        self.assertEqual(len(track), 8)
        times = [p["device_time"] for p in track]
        self.assertEqual(times, sorted(times))

    def test_unreachable_speed_detected(self):
        self.register_site()
        result = self.svc.ingest_observations(
            [
                obs("RID-S", 0, 0, 31.0, 121.0, "st-1"),
                obs("RID-S", 1, 30, 31.027, 121.0, "st-1"),  # 30 秒 3 公里 ≈ 100 m/s
            ],
            SYS,
        )
        rules = [c["rule"] for c in result["cases"]]
        self.assertEqual(rules, ["unreachable_speed"])

    def test_position_jump_detected(self):
        self.register_site()
        result = self.svc.ingest_observations(
            [
                obs("RID-J", 0, 0, 31.0, 121.0, "st-1"),
                obs("RID-J", 1, 30, 31.18, 121.0, "st-1"),  # 30 秒 20 公里
            ],
            SYS,
        )
        rules = [c["rule"] for c in result["cases"]]
        self.assertEqual(rules, ["position_jump"])


class CertificateTest(ServiceTestBase):
    def test_expired_certificate_detected(self):
        self.register_site()
        self.svc.add_certificate(
            "dev-1",
            {
                "cert_id": "cert-old",
                "remote_id": "RID-OLD",
                "valid_from": ts(-7200),
                "valid_to": ts(-3600),
            },
            REG,
        )
        result = self.svc.ingest_observations(
            [obs("RID-OLD", 0, 0, 31.0, 121.0, "st-1", "cert-old")], SYS
        )
        rules = [c["rule"] for c in result["cases"]]
        self.assertEqual(rules, ["expired_certificate"])
        case = self.svc.case_view(result["cases"][0]["case_id"], INV)
        self.assertEqual(case["findings"][0]["details"]["reason"], "cert_expired")

    def test_certificate_rotation_keeps_identity_continuous(self):
        self.register_site()
        self.svc.add_certificate(
            "dev-1",
            {
                "cert_id": "cert-old",
                "remote_id": "RID-X",
                "valid_from": ts(-10800),
                "valid_to": ts(-3600),
                "replaces_cert_id": None,
            },
            REG,
        )
        self.svc.add_certificate(
            "dev-1",
            {
                "cert_id": "cert-1",
                "remote_id": "RID-X",
                "valid_from": ts(-3600),
                "valid_to": ts(7200),
                "replaces_cert_id": "cert-old",
            },
            REG,
        )
        # 轮换前后各一条广播，位置连续：不应产生任何异常
        result = self.svc.ingest_observations(
            [
                obs("RID-X", 0, -3700, 31.0, 121.0, "st-1", "cert-old"),
                obs("RID-X", 1, -3500, 31.0001, 121.0, "st-1", "cert-1"),
            ],
            SYS,
        )
        self.assertEqual(result["cases"], [])
        view = self.svc.remote_id_view("RID-X", REG)
        chain = view["registration"]["certificate_chain"]
        self.assertEqual(len(chain), 2)  # cert-old → cert-1
        # 同一设备贯穿整条证书链：身份连续
        self.assertEqual({c["device_id"] for c in chain}, {"dev-1"})
        rotated = next(c for c in chain if c["cert_id"] == "cert-1")
        self.assertEqual(rotated["replaces_cert_id"], "cert-old")


class ClockDriftTest(ServiceTestBase):
    def test_drift_only_lowers_confidence_not_conclusion(self):
        self.register_site(clock_uncertainty_ms=5000.0)
        result = self.ingest_duplicate_scene()
        dup_cases = [c for c in result["cases"] if c["rule"] == "duplicate_identity"]
        self.assertEqual(len(dup_cases), 1)  # 漂移不制造也不阻止结论
        case = self.svc.case_view(dup_cases[0]["case_id"], INV)
        finding = next(f for f in case["findings"] if f["rule"] == "duplicate_identity")
        self.assertEqual(finding["confidence"], 0.5)
        self.assertIn("receiver_clock_drift", finding["limiting_factors"])
        # 低置信证据自动降级，等待人工复核而不是直接定性
        self.assertEqual(case["severity"], "medium")


class DispositionTest(ServiceTestBase):
    def test_escalate_exclude_merge_are_append_only(self):
        self.register_site()
        # 案件 1：重复身份（high）
        result1 = self.ingest_duplicate_scene()
        case1 = result1["cases"][0]["case_id"]
        # 案件 2：不可达速度（medium）
        result2 = self.svc.ingest_observations(
            [
                obs("RID-S", 0, 0, 31.0, 121.0, "st-1"),
                obs("RID-S", 1, 30, 31.027, 121.0, "st-1"),
            ],
            SYS,
        )
        case2 = result2["cases"][0]["case_id"]

        # 升级：medium → high，复核时限随之收紧
        before = self.svc.case_view(case2, INV)
        updated = self.svc.dispose(case2, {"action": "escalate"}, INV, "inv-7")
        self.assertEqual(updated["status"], "ESCALATED")
        self.assertEqual(updated["severity"], "high")
        self.assertLess(updated["review_due_at"], before["review_due_at"])

        # 人工追加证据
        self.svc.append_evidence(
            case2, {"kind": "evidence", "text": "现场核查未发现申报航迹"}, REG, "reg-3"
        )

        # 合并：案件 2 并入案件 1
        merged = self.svc.dispose(
            case1, {"action": "merge", "into_case_id": case2, "reason": "同一冒用源"},
            INV, "inv-7",
        )
        self.assertIn(case1, merged["absorbed_cases"])
        source = self.svc.case_view(case1, INV)
        self.assertEqual(source["status"], "MERGED")
        self.assertEqual(source["merged_into"], case2)

        # 排除：误报排除后进入终态
        excluded = self.svc.dispose(
            case2, {"action": "exclude", "reason": "接收站故障导致误报"}, INV, "inv-7"
        )
        self.assertEqual(excluded["status"], "EXCLUDED")

        # 全部处置都沉淀在时间线里（追加式）
        kinds = [e["kind"] for e in excluded["timeline"]]
        actions = [e["payload"].get("action") for e in excluded["timeline"]]
        self.assertIn("disposition", kinds)
        self.assertIn("evidence", kinds)
        self.assertIn("escalate", actions)
        self.assertIn("absorb", actions)
        self.assertIn("exclude", actions)

        # 终态案件不能再处置；已合并案件不能追加证据
        with self.assertRaises(ConflictError):
            self.svc.dispose(case2, {"action": "resolve", "reason": "x"}, INV, "inv-7")
        with self.assertRaises(ConflictError):
            self.svc.append_evidence(case1, {"kind": "note", "text": "y"}, INV, "inv-7")


class PrivacyTest(ServiceTestBase):
    def test_contact_visible_only_to_investigator(self):
        self.register_site()
        self.ingest_duplicate_scene()
        regulator_view = self.svc.remote_id_view("RID-X", REG)
        operator = regulator_view["registration"]["operators"][0]
        self.assertTrue(operator["contact_redacted"])
        self.assertNotIn("phone", operator)
        self.assertNotIn("email", operator)

        investigator_view = self.svc.remote_id_view("RID-X", INV)
        operator = investigator_view["registration"]["operators"][0]
        self.assertEqual(operator["phone"], "13800001111")
        self.assertFalse(operator["contact_redacted"])


class PersistenceTest(ServiceTestBase):
    def test_open_cases_and_deadlines_survive_restart(self):
        self.register_site()
        self.ingest_duplicate_scene()
        cases_before = self.svc.list_cases(status="OPEN")
        self.assertEqual(len(cases_before), 1)
        due_before = cases_before[0]["review_due_at"]
        self.svc.close()

        # 重启：同一数据库路径，未结案件与复核时限照常
        svc2 = self._open_service()
        self.addCleanup(svc2.close)
        cases_after = svc2.list_cases(status="OPEN")
        self.assertEqual(len(cases_after), 1)
        self.assertEqual(cases_after[0]["review_due_at"], due_before)
        self.assertFalse(cases_after[0]["overdue"])

    def test_overdue_cases_are_flagged(self):
        self.svc.close()
        self.svc = self._open_service(
            sla_hours={"high": 0.0, "medium": 0.0, "low": 0.0}
        )
        self.addCleanup(self.svc.close)
        self.register_site()
        self.ingest_duplicate_scene()
        overdue = self.svc.list_cases(overdue=True)
        self.assertEqual(len(overdue), 1)
        self.assertTrue(overdue[0]["overdue"])


class IdempotencyTest(ServiceTestBase):
    def test_repeated_ingest_is_idempotent(self):
        self.register_site()
        batch = [
            obs("RID-X", i, i * 20, 31.0 + i * 0.0001, 121.0, "st-1", "cert-1")
            for i in range(3)
        ] + [
            obs("RID-X", i, i * 20 + 5, 31.0 + i * 0.0001, 121.1, "st-2", "cert-1")
            for i in range(3)
        ]
        first = self.svc.ingest_observations(batch, SYS)
        self.assertEqual(len(first["accepted"]), 6)
        case_id = first["cases"][0]["case_id"]
        events_before = self.svc.case_view(case_id, INV)["timeline"]

        second = self.svc.ingest_observations(batch, SYS)
        self.assertEqual(len(second["accepted"]), 0)
        self.assertEqual(len(second["duplicates"]), 6)
        self.assertEqual(second["cases"], [])
        self.assertEqual(len(self.svc.list_cases()), 1)
        view = self.svc.case_view(case_id, INV)
        self.assertEqual(len(view["timeline"]), len(events_before))
        self.assertEqual(len(view["findings"]), 1)


if __name__ == "__main__":
    unittest.main()
