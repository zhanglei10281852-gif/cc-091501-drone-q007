"""业务编排：登记、观测摄入、检测归并、案件处置与检索视图。"""
from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Any, Optional

from .detection import detect_anomalies
from .models import (
    CASE_MERGE_GAP_SECONDS,
    DEFAULT_SLA_HOURS,
    DISPOSITION_ROLES,
    EVIDENCE_ROLES,
    INGEST_ROLES,
    PII_ROLES,
    REGISTER_ROLES,
    RULE_BASE_SEVERITY,
    RULE_PARAMS,
    SEVERITY_ORDER,
    CaseStatus,
    ConflictError,
    Finding,
    ForbiddenError,
    NotFoundError,
    Observation,
    Role,
    TERMINAL_STATUSES,
    ValidationError,
    content_hash,
    iso,
    new_id,
    now_utc,
    parse_ts,
)
from .storage import Storage, dumps_payload
from .tracking import build_track


def _require_role(role: Role, allowed: set[Role], action: str) -> None:
    if role not in allowed:
        raise ForbiddenError(f"角色 {role.value} 无权执行: {action}")


def _require_str(data: dict[str, Any], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"缺少必填字段 {field}（非空字符串）")
    return value.strip()


def _optional_str(data: dict[str, Any], field: str) -> Optional[str]:
    value = data.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError(f"字段 {field} 必须是字符串")
    return value.strip() or None


def _require_float(data: dict[str, Any], field: str, lo: float, hi: float) -> float:
    value = data.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"字段 {field} 必须是数值")
    value = float(value)
    if not (lo <= value <= hi):
        raise ValidationError(f"字段 {field} 超出范围 [{lo}, {hi}]")
    return value


def _optional_float(data: dict[str, Any], field: str) -> Optional[float]:
    value = data.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"字段 {field} 必须是数值")
    return float(value)


class RidService:
    def __init__(
        self,
        db_path: str,
        sla_hours: Optional[dict[str, float]] = None,
        rule_params: Optional[dict[str, dict[str, Any]]] = None,
    ):
        self.storage = Storage(db_path)
        self.sla_hours = dict(sla_hours or DEFAULT_SLA_HOURS)
        self.rule_params = rule_params or RULE_PARAMS

    def close(self) -> None:
        self.storage.close()

    # ================= 登记 =================

    def register_operator(self, data: dict[str, Any], role: Role) -> dict[str, Any]:
        _require_role(role, REGISTER_ROLES, "登记操作员")
        operator_id = _optional_str(data, "operator_id") or new_id("op")
        row = {
            "operator_id": operator_id,
            "name": _require_str(data, "name"),
            "phone": _optional_str(data, "phone"),
            "email": _optional_str(data, "email"),
            "id_number": _optional_str(data, "id_number"),
            "created_at": iso(now_utc()),
        }
        self.storage.upsert_operator(row)
        return self._operator_view(self.storage.get_operator(operator_id), Role.INVESTIGATOR)

    def register_device(self, data: dict[str, Any], role: Role) -> dict[str, Any]:
        _require_role(role, REGISTER_ROLES, "登记设备")
        device_id = _optional_str(data, "device_id") or new_id("dev")
        operator_id = _require_str(data, "operator_id")
        if self.storage.get_operator(operator_id) is None:
            raise ValidationError(f"操作员不存在: {operator_id}")
        row = {
            "device_id": device_id,
            "operator_id": operator_id,
            "serial_number": _require_str(data, "serial_number"),
            "model": _optional_str(data, "model"),
            "created_at": iso(now_utc()),
        }
        self.storage.upsert_device(row)
        return self.storage.get_device(device_id)

    def add_certificate(self, device_id: str, data: dict[str, Any], role: Role) -> dict[str, Any]:
        """登记或轮换证书。轮换时以 replaces_cert_id 链接旧证书，广播身份
        （remote_id）不变，设备身份通过证书链保持连续。"""
        _require_role(role, REGISTER_ROLES, "登记证书")
        device = self.storage.get_device(device_id)
        if device is None:
            raise NotFoundError(f"设备不存在: {device_id}")
        cert_id = _optional_str(data, "cert_id") or new_id("cert")
        valid_from = parse_ts(data.get("valid_from"), "valid_from")
        valid_to = parse_ts(data.get("valid_to"), "valid_to")
        if valid_from >= valid_to:
            raise ValidationError("valid_from 必须早于 valid_to")
        replaces = _optional_str(data, "replaces_cert_id")
        remote_id = _optional_str(data, "remote_id")
        if replaces:
            old = self.storage.get_certificate(replaces)
            if old is None:
                raise ValidationError(f"被替换的证书不存在: {replaces}")
            if old["device_id"] != device_id:
                raise ValidationError("被替换的证书不属于该设备")
            remote_id = remote_id or old["remote_id"]
        if not remote_id:
            raise ValidationError("缺少必填字段 remote_id（轮换时可省略，继承旧证书）")
        row = {
            "cert_id": cert_id,
            "device_id": device_id,
            "remote_id": remote_id,
            "valid_from": iso(valid_from),
            "valid_to": iso(valid_to),
            "replaces_cert_id": replaces,
            "created_at": iso(now_utc()),
        }
        self.storage.upsert_certificate(row)
        return self.storage.get_certificate(cert_id)

    def create_authorization(self, data: dict[str, Any], role: Role) -> dict[str, Any]:
        _require_role(role, REGISTER_ROLES, "登记飞行授权")
        auth_id = _optional_str(data, "auth_id") or new_id("auth")
        device_id = _require_str(data, "device_id")
        if self.storage.get_device(device_id) is None:
            raise ValidationError(f"设备不存在: {device_id}")
        start = parse_ts(data.get("start_time"), "start_time")
        end = parse_ts(data.get("end_time"), "end_time")
        if start >= end:
            raise ValidationError("start_time 必须早于 end_time")
        area = data.get("area")
        if area is None:
            raise ValidationError("缺少必填字段 area")
        row = {
            "auth_id": auth_id,
            "device_id": device_id,
            "area": json.dumps(area, ensure_ascii=False, sort_keys=True),
            "start_time": iso(start),
            "end_time": iso(end),
            "created_at": iso(now_utc()),
        }
        self.storage.upsert_authorization(row)
        return self._auth_view(row)

    def register_receiver(self, data: dict[str, Any], role: Role) -> dict[str, Any]:
        _require_role(role, REGISTER_ROLES, "登记接收站")
        receiver_id = _optional_str(data, "receiver_id") or new_id("rx")
        uncertainty = data.get("clock_uncertainty_ms", 0)
        if isinstance(uncertainty, bool) or not isinstance(uncertainty, (int, float)):
            raise ValidationError("clock_uncertainty_ms 必须是数值")
        if float(uncertainty) < 0:
            raise ValidationError("clock_uncertainty_ms 不能为负")
        row = {
            "receiver_id": receiver_id,
            "name": _optional_str(data, "name"),
            "lat": _require_float(data, "lat", -90.0, 90.0),
            "lon": _require_float(data, "lon", -180.0, 180.0),
            "clock_uncertainty_ms": float(uncertainty),
            "created_at": iso(now_utc()),
        }
        self.storage.upsert_receiver(row)
        return self.storage.get_receiver(receiver_id)

    # ================= 观测摄入 =================

    def ingest_observations(
        self, items: list[Any], role: Role, actor: str = "system"
    ) -> dict[str, Any]:
        _require_role(role, INGEST_ROLES, "摄入广播观测")
        if not isinstance(items, list):
            raise ValidationError("请求体必须是观测数组")
        accepted: list[str] = []
        duplicates: list[str] = []
        rejected: list[dict[str, Any]] = []
        touched: set[str] = set()
        for index, item in enumerate(items):
            try:
                obs = self._validate_observation(item)
            except ValidationError as exc:
                rejected.append({"index": index, "error": str(exc)})
                continue
            if self.storage.insert_observation(obs):
                accepted.append(obs.obs_id)
                touched.add(obs.remote_id)
            else:
                duplicates.append(obs.obs_id)
        cases: list[dict[str, Any]] = []
        for remote_id in sorted(touched):
            cases.extend(self._run_detection(remote_id, actor))
        return {
            "accepted": accepted,
            "duplicates": duplicates,
            "rejected": rejected,
            "cases": cases,
        }

    def _validate_observation(self, item: Any) -> Observation:
        if not isinstance(item, dict):
            raise ValidationError("观测必须是对象")
        remote_id = _require_str(item, "remote_id")
        seq = item.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ValidationError("seq 必须是非负整数")
        lat = _require_float(item, "lat", -90.0, 90.0)
        lon = _require_float(item, "lon", -180.0, 180.0)
        receiver_id = _require_str(item, "receiver_id")
        if self.storage.get_receiver(receiver_id) is None:
            raise ValidationError(f"接收站未登记: {receiver_id}")
        device_time = None
        if item.get("device_time") is not None:
            device_time = parse_ts(item.get("device_time"), "device_time")
        received_at = parse_ts(item.get("received_at"), "received_at")
        cert_id = _optional_str(item, "cert_id")
        digest = content_hash(
            {
                "remote_id": remote_id,
                "seq": seq,
                "device_time": iso(device_time) if device_time else None,
                "lat": lat,
                "lon": lon,
                "alt": _optional_float(item, "alt"),
                "speed_mps": _optional_float(item, "speed_mps"),
                "cert_id": cert_id,
            }
        )
        obs_id = "obs-" + hashlib.sha256(
            f"{receiver_id}|{remote_id}|{seq}|{digest}".encode("utf-8")
        ).hexdigest()[:16]
        return Observation(
            obs_id=obs_id,
            remote_id=remote_id,
            seq=seq,
            device_time=device_time,
            lat=lat,
            lon=lon,
            alt=_optional_float(item, "alt"),
            speed_mps=_optional_float(item, "speed_mps"),
            cert_id=cert_id,
            receiver_id=receiver_id,
            received_at=received_at,
            content_hash=digest,
            ingested_at=now_utc(),
        )

    # ================= 检测与案件归并 =================

    def _run_detection(self, remote_id: str, actor: str) -> list[dict[str, Any]]:
        observations = self.storage.observations_by_remote_id(remote_id)
        cert_ids = {o.cert_id for o in observations if o.cert_id}
        certificates = {
            cid: cert
            for cid in cert_ids
            if (cert := self.storage.get_certificate(cid)) is not None
        }
        receivers = {r["receiver_id"]: r for r in self.storage.receivers_all()}
        findings = detect_anomalies(
            remote_id, observations, certificates, receivers, self.rule_params
        )
        results = []
        for finding in findings:
            attached = self._attach_finding(finding, actor)
            if attached is not None:
                results.append(attached)
        return results

    def _severity_for(self, finding: Finding) -> str:
        base = RULE_BASE_SEVERITY.get(finding.rule, "medium")
        # 低置信证据（如接收站时钟漂移显著）自动降一级，等待人工复核
        if finding.confidence < 0.6 and SEVERITY_ORDER[base] > 0:
            return {2: "medium", 1: "low"}[SEVERITY_ORDER[base]]
        return base

    def _compute_due(self, opened_at, severity: str):
        return opened_at + timedelta(hours=self.sla_hours[severity])

    def _attach_finding(self, finding: Finding, actor: str) -> Optional[dict[str, Any]]:
        fingerprint = finding.fingerprint()
        if self.storage.finding_exists(fingerprint):
            return None  # 幂等：相同证据不重复追加
        now = now_utc()
        case = self._find_mergeable_case(finding)
        created = False
        if case is None:
            case_id = new_id("case")
            severity = self._severity_for(finding)
            self.storage.insert_case(
                {
                    "case_id": case_id,
                    "remote_id": finding.remote_id,
                    "status": CaseStatus.OPEN.value,
                    "severity": severity,
                    "opened_at": iso(now),
                    "review_due_at": iso(self._compute_due(now, severity)),
                    "merged_into": None,
                    "closed_at": None,
                }
            )
            self._append_event(
                case_id,
                "opened",
                {
                    "rule": finding.rule,
                    "severity": severity,
                    "reason": "检测规则命中，建立人工复核案件",
                },
                actor="system",
                ts=now,
            )
            created = True
        else:
            case_id = case["case_id"]
            self._maybe_raise_severity(case, finding, now)

        payload = finding.to_payload()
        payload["fingerprint"] = fingerprint
        self.storage.insert_finding(
            {
                "fingerprint": fingerprint,
                "case_id": case_id,
                "rule": finding.rule,
                "remote_id": finding.remote_id,
                "window_start": iso(finding.window_start),
                "window_end": iso(finding.window_end),
                "confidence": finding.confidence,
                "payload": dumps_payload(payload),
                "created_at": iso(now),
            }
        )
        self._append_event(case_id, "finding", payload, actor=actor, ts=now)
        return {"case_id": case_id, "rule": finding.rule, "created": created}

    def _find_mergeable_case(self, finding: Finding) -> Optional[dict[str, Any]]:
        """同广播身份、同规则、时间窗相邻的未结案件：追加证据而不是开新案。"""
        for case in self.storage.open_cases_by_remote_id(finding.remote_id):
            for existing in self.storage.findings_by_case(case["case_id"]):
                if existing["rule"] != finding.rule:
                    continue
                start = parse_ts(existing["window_start"])
                end = parse_ts(existing["window_end"])
                gap = max(
                    0.0,
                    (finding.window_start - end).total_seconds(),
                    (start - finding.window_end).total_seconds(),
                )
                if gap <= CASE_MERGE_GAP_SECONDS:
                    return case
        return None

    def _maybe_raise_severity(
        self, case: dict[str, Any], finding: Finding, now
    ) -> None:
        new_severity = self._severity_for(finding)
        current = case["severity"]
        if SEVERITY_ORDER[new_severity] <= SEVERITY_ORDER[current]:
            return
        opened_at = parse_ts(case["opened_at"])
        self.storage.update_case(
            case["case_id"],
            severity=new_severity,
            review_due_at=iso(self._compute_due(opened_at, new_severity)),
        )
        self._append_event(
            case["case_id"],
            "severity_raised",
            {"from": current, "to": new_severity, "trigger_rule": finding.rule},
            actor="system",
            ts=now,
        )

    def _append_event(
        self, case_id: str, kind: str, payload: dict[str, Any], actor: str, ts=None
    ) -> None:
        self.storage.append_event(
            {
                "event_id": new_id("evt"),
                "case_id": case_id,
                "ts": iso(ts or now_utc()),
                "actor": actor,
                "kind": kind,
                "payload": dumps_payload(payload),
            }
        )

    # ================= 案件处置（全部追加式） =================

    def append_evidence(
        self,
        case_id: str,
        data: dict[str, Any],
        role: Role,
        actor: str,
    ) -> dict[str, Any]:
        _require_role(role, EVIDENCE_ROLES, "追加证据")
        case = self._get_case_or_404(case_id)
        if case["status"] == CaseStatus.MERGED.value:
            raise ConflictError(f"案件已合并至 {case['merged_into']}，请向目标案件追加")
        kind = data.get("kind", "note")
        if kind not in ("note", "evidence"):
            raise ValidationError("kind 必须是 note 或 evidence")
        text = data.get("text")
        if not isinstance(text, str) or not text.strip():
            raise ValidationError("缺少必填字段 text")
        payload = {"text": text.strip()}
        if isinstance(data.get("data"), dict):
            payload["data"] = data["data"]
        self._append_event(case_id, kind, payload, actor=actor)
        return self.case_view(case_id, role)

    def dispose(
        self,
        case_id: str,
        data: dict[str, Any],
        role: Role,
        actor: str,
    ) -> dict[str, Any]:
        _require_role(role, DISPOSITION_ROLES, "案件处置")
        case = self._get_case_or_404(case_id)
        action = data.get("action")
        status = CaseStatus(case["status"])
        if action == "merge":
            return self._merge(case, data, actor)
        if status in TERMINAL_STATUSES:
            raise ConflictError(f"案件已处于终态 {status.value}，不能再处置")
        reason = data.get("reason")
        if action in ("exclude", "resolve") and (not isinstance(reason, str) or not reason.strip()):
            raise ValidationError(f"{action} 必须给出 reason")
        now = now_utc()
        if action == "triage":
            if status != CaseStatus.OPEN:
                raise ConflictError("仅 OPEN 状态可分诊")
            self.storage.update_case(case_id, status=CaseStatus.TRIAGED.value)
            self._append_event(case_id, "disposition", {"action": "triage"}, actor, now)
        elif action == "escalate":
            current = case["severity"]
            order = ["low", "medium", "high"]
            new_severity = order[min(SEVERITY_ORDER[current] + 1, 2)]
            opened_at = parse_ts(case["opened_at"])
            self.storage.update_case(
                case_id,
                status=CaseStatus.ESCALATED.value,
                severity=new_severity,
                review_due_at=iso(self._compute_due(opened_at, new_severity)),
            )
            self._append_event(
                case_id,
                "disposition",
                {
                    "action": "escalate",
                    "from_severity": current,
                    "to_severity": new_severity,
                    "reason": reason if isinstance(reason, str) else None,
                },
                actor,
                now,
            )
        elif action == "exclude":
            self.storage.update_case(
                case_id, status=CaseStatus.EXCLUDED.value, closed_at=iso(now)
            )
            self._append_event(
                case_id, "disposition",
                {"action": "exclude", "reason": reason.strip()}, actor, now,
            )
        elif action == "resolve":
            self.storage.update_case(
                case_id, status=CaseStatus.RESOLVED.value, closed_at=iso(now)
            )
            self._append_event(
                case_id, "disposition",
                {"action": "resolve", "reason": reason.strip()}, actor, now,
            )
        else:
            raise ValidationError(f"未知处置动作: {action!r}")
        return self.case_view(case_id, role)

    def _merge(self, source: dict[str, Any], data: dict[str, Any], actor: str) -> dict[str, Any]:
        if CaseStatus(source["status"]) in TERMINAL_STATUSES:
            raise ConflictError(f"案件已处于终态 {source['status']}，不能合并")
        into_id = data.get("into_case_id")
        if not isinstance(into_id, str) or not into_id.strip():
            raise ValidationError("merge 必须给出 into_case_id")
        into_id = into_id.strip()
        if into_id == source["case_id"]:
            raise ValidationError("案件不能合并到自身")
        target = self._get_case_or_404(into_id)
        if CaseStatus(target["status"]) in TERMINAL_STATUSES:
            raise ConflictError(f"目标案件已处于终态 {target['status']}")
        now = now_utc()
        reason = data.get("reason")
        self.storage.update_case(
            source["case_id"],
            status=CaseStatus.MERGED.value,
            merged_into=into_id,
            closed_at=iso(now),
        )
        self._append_event(
            source["case_id"],
            "disposition",
            {
                "action": "merge",
                "into_case_id": into_id,
                "reason": reason if isinstance(reason, str) else None,
            },
            actor,
            now,
        )
        self._append_event(
            into_id,
            "disposition",
            {"action": "absorb", "from_case_id": source["case_id"]},
            actor,
            now,
        )
        return self.case_view(into_id, Role.INVESTIGATOR)

    # ================= 检索视图 =================

    def list_cases(
        self, status: Optional[str] = None, overdue: bool = False
    ) -> list[dict[str, Any]]:
        rows = self.storage.list_cases(status)
        now = now_utc()
        views = [self._case_summary(row, now) for row in rows]
        if overdue:
            views = [v for v in views if v["overdue"]]
        return views

    def case_view(self, case_id: str, role: Role) -> dict[str, Any]:
        case = self._get_case_or_404(case_id)
        now = now_utc()
        findings = [
            json.loads(row["payload"]) for row in self.storage.findings_by_case(case_id)
        ]
        timeline = [
            {
                "ts": row["ts"],
                "actor": row["actor"],
                "kind": row["kind"],
                "payload": json.loads(row["payload"]),
            }
            for row in self.storage.events_by_case(case_id)
        ]
        view = self._case_summary(case, now)
        view.update(
            {
                "rules": sorted({f["rule"] for f in findings}),
                "findings": findings,
                "timeline": timeline,
                "registration": self._registration_view(case["remote_id"], role),
                "merged_into": case["merged_into"],
                "absorbed_cases": self._absorbed_cases(case_id),
            }
        )
        return view

    def remote_id_view(self, remote_id: str, role: Role) -> dict[str, Any]:
        cases = self.storage.cases_by_remote_id(remote_id)
        findings = self.storage.findings_by_remote_id(remote_id)
        now = now_utc()
        observations = self.storage.observations_by_remote_id(remote_id, limit=500)
        track = build_track(observations)
        return {
            "remote_id": remote_id,
            "registered": bool(self.storage.certificates_by_remote_id(remote_id)),
            "registration": self._registration_view(remote_id, role),
            "conflict_windows": self._conflict_windows(findings),
            "cases": [self._case_summary(c, now) for c in cases],
            "observation_count": self.storage.count_observations(remote_id),
            "recent_track": [
                {
                    "device_time": iso(p.device_time),
                    "seq": p.seq,
                    "lat": p.lat,
                    "lon": p.lon,
                    "receiver_ids": p.receiver_ids,
                    "corroboration": len(p.observation_ids),
                }
                for p in track[-50:]
            ],
        }

    def _case_summary(self, case: dict[str, Any], now) -> dict[str, Any]:
        due = parse_ts(case["review_due_at"])
        terminal = case["status"] in {s.value for s in TERMINAL_STATUSES}
        findings = self.storage.findings_by_case(case["case_id"])
        return {
            "case_id": case["case_id"],
            "remote_id": case["remote_id"],
            "status": case["status"],
            "severity": case["severity"],
            "opened_at": case["opened_at"],
            "review_due_at": case["review_due_at"],
            "overdue": (not terminal) and due < now,
            "closed_at": case["closed_at"],
            "rules": sorted({row["rule"] for row in findings}),
            "finding_count": len(findings),
        }

    def _absorbed_cases(self, case_id: str) -> list[str]:
        absorbed = []
        for row in self.storage.events_by_case(case_id):
            if row["kind"] == "disposition":
                payload = json.loads(row["payload"])
                if payload.get("action") == "absorb":
                    absorbed.append(payload.get("from_case_id"))
        return absorbed

    @staticmethod
    def _conflict_windows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """把该广播身份所有发现的时间窗合并，回答“冲突发生在哪段时间”。"""
        spans = []
        for row in findings:
            spans.append(
                (parse_ts(row["window_start"]), parse_ts(row["window_end"]), row)
            )
        spans.sort(key=lambda item: item[0])
        merged: list[dict[str, Any]] = []
        for start, end, row in spans:
            if merged and start <= merged[-1]["_end"]:
                current = merged[-1]
                current["_end"] = max(current["_end"], end)
                current["rules"] = sorted(set(current["rules"]) | {row["rule"]})
                if row["case_id"] not in current["case_ids"]:
                    current["case_ids"].append(row["case_id"])
            else:
                merged.append(
                    {
                        "_end": end,
                        "start": iso(start),
                        "end": iso(end),
                        "rules": [row["rule"]],
                        "case_ids": [row["case_id"]],
                    }
                )
        for window in merged:
            window["end"] = iso(window.pop("_end"))
        return merged

    def _registration_view(self, remote_id: str, role: Role) -> Optional[dict[str, Any]]:
        certs = self.storage.certificates_by_remote_id(remote_id)
        if not certs:
            return None
        devices: dict[str, dict[str, Any]] = {}
        operators: dict[str, dict[str, Any]] = {}
        authorizations: list[dict[str, Any]] = []
        for cert in certs:
            device = self.storage.get_device(cert["device_id"])
            if device is None:
                continue
            devices[device["device_id"]] = device
            operator = self.storage.get_operator(device["operator_id"])
            if operator is not None:
                operators[operator["operator_id"]] = self._operator_view(operator, role)
            for auth in self.storage.authorizations_by_device(device["device_id"]):
                authorizations.append(self._auth_view(auth))
        return {
            "devices": [
                {
                    "device_id": d["device_id"],
                    "serial_number": d["serial_number"],
                    "model": d["model"],
                    "operator_id": d["operator_id"],
                }
                for d in devices.values()
            ],
            "operators": list(operators.values()),
            "certificate_chain": [
                {
                    "cert_id": c["cert_id"],
                    "device_id": c["device_id"],
                    "valid_from": c["valid_from"],
                    "valid_to": c["valid_to"],
                    "replaces_cert_id": c["replaces_cert_id"],
                }
                for c in certs
            ],
            "authorizations": authorizations,
        }

    @staticmethod
    def _operator_view(operator: Optional[dict[str, Any]], role: Role) -> dict[str, Any]:
        if operator is None:
            return {}
        view = {"operator_id": operator["operator_id"], "name": operator["name"]}
        if role in PII_ROLES:
            view.update(
                {
                    "phone": operator["phone"],
                    "email": operator["email"],
                    "id_number": operator["id_number"],
                    "contact_redacted": False,
                }
            )
        else:
            view["contact_redacted"] = True
        return view

    @staticmethod
    def _auth_view(row: dict[str, Any]) -> dict[str, Any]:
        area = row["area"]
        return {
            "auth_id": row["auth_id"],
            "device_id": row["device_id"],
            "area": json.loads(area) if isinstance(area, str) else area,
            "start_time": row["start_time"],
            "end_time": row["end_time"],
        }

    def _get_case_or_404(self, case_id: str) -> dict[str, Any]:
        case = self.storage.get_case(case_id)
        if case is None:
            raise NotFoundError(f"案件不存在: {case_id}")
        return case
