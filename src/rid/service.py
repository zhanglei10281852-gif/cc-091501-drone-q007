"""业务编排：登记、观测接入、检测触发、身份检索视图与角色脱敏。"""

import json
import uuid
from datetime import timedelta

from . import cases as case_mod
from . import rules as rule_mod
from .config import DEFAULT_PARAMS, PII_VISIBLE_ROLES
from .geo import haversine_m
from .timeutil import parse_iso, to_iso, utcnow
from .tracks import build_tracklets, tracklet_summary


class ServiceError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _new_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _require(data, *fields):
    for field in fields:
        if data.get(field) is None:
            raise ServiceError(400, "missing_field", f"缺少必填字段: {field}")


def _lat(value, field="lat"):
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ServiceError(400, "invalid_field", f"{field} 必须为数字") from None
    if not -90.0 <= number <= 90.0:
        raise ServiceError(400, "invalid_field", f"{field} 超出范围 [-90, 90]")
    return number


def _lon(value, field="lon"):
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ServiceError(400, "invalid_field", f"{field} 必须为数字") from None
    if not -180.0 <= number <= 180.0:
        raise ServiceError(400, "invalid_field", f"{field} 超出范围 [-180, 180]")
    return number


def _time(value, field):
    try:
        return parse_iso(value, field)
    except ValueError as exc:
        raise ServiceError(400, "invalid_field", str(exc)) from None


class Service:
    def __init__(self, storage, params=None):
        self.storage = storage
        self.params = dict(DEFAULT_PARAMS if params is None else params)

    # ---------- 登记 ----------

    def create_operator(self, data):
        _require(data, "name")
        operator_id = data.get("operator_id") or _new_id("op")
        if self.storage.one("SELECT operator_id FROM operators WHERE operator_id = ?", (operator_id,)):
            raise ServiceError(409, "duplicate_operator", f"操作员已存在: {operator_id}")
        contact = data.get("contact") or {}
        if not isinstance(contact, dict):
            raise ServiceError(400, "invalid_field", "contact 必须为对象")
        self.storage.execute(
            "INSERT INTO operators (operator_id, name, organization, contact_json, created_at) VALUES (?,?,?,?,?)",
            (operator_id, data["name"], data.get("organization"),
             json.dumps(contact, ensure_ascii=False), to_iso(utcnow())),
        )
        return self.get_operator(operator_id, role=_PII_ROLE)

    def get_operator(self, operator_id, role):
        row = self.storage.one("SELECT * FROM operators WHERE operator_id = ?", (operator_id,))
        if row is None:
            raise ServiceError(404, "operator_not_found", f"操作员不存在: {operator_id}")
        return _operator_view(row, role)

    def list_operators(self, role):
        return [_operator_view(r, role) for r in self.storage.all("SELECT * FROM operators ORDER BY created_at")]

    def create_device(self, data):
        _require(data, "serial", "operator_id", "remote_id")
        if not self.storage.one("SELECT operator_id FROM operators WHERE operator_id = ?", (data["operator_id"],)):
            raise ServiceError(404, "operator_not_found", f"操作员不存在: {data['operator_id']}")
        device_id = data.get("device_id") or _new_id("dev")
        if self.storage.one("SELECT device_id FROM devices WHERE device_id = ?", (device_id,)):
            raise ServiceError(409, "duplicate_device", f"设备已存在: {device_id}")
        if self.storage.one("SELECT device_id FROM devices WHERE remote_id = ?", (data["remote_id"],)):
            raise ServiceError(409, "duplicate_remote_id", f"广播身份已被注册: {data['remote_id']}")
        if self.storage.one("SELECT device_id FROM devices WHERE serial = ?", (data["serial"],)):
            raise ServiceError(409, "duplicate_serial", f"设备序列号已登记: {data['serial']}")
        self.storage.execute(
            "INSERT INTO devices (device_id, serial, model, operator_id, remote_id, created_at) VALUES (?,?,?,?,?,?)",
            (device_id, data["serial"], data.get("model"), data["operator_id"], data["remote_id"], to_iso(utcnow())),
        )
        return self._device_view(self.storage.one("SELECT * FROM devices WHERE device_id = ?", (device_id,)))

    def get_device(self, device_id):
        row = self.storage.one("SELECT * FROM devices WHERE device_id = ?", (device_id,))
        if row is None:
            raise ServiceError(404, "device_not_found", f"设备不存在: {device_id}")
        return self._device_view(row)

    def _device_view(self, row):
        certs = self.storage.all(
            "SELECT * FROM certificates WHERE device_id = ? ORDER BY valid_from", (row["device_id"],))
        return {
            "device_id": row["device_id"],
            "serial": row["serial"],
            "model": row["model"],
            "operator_id": row["operator_id"],
            "remote_id": row["remote_id"],
            "created_at": row["created_at"],
            "certificates": [
                {"certificate_id": c["certificate_id"], "cert_ref": c["cert_ref"],
                 "valid_from": c["valid_from"], "valid_to": c["valid_to"]}
                for c in certs
            ],
        }

    def add_certificate(self, device_id, data):
        _require(data, "valid_from", "valid_to")
        if not self.storage.one("SELECT device_id FROM devices WHERE device_id = ?", (device_id,)):
            raise ServiceError(404, "device_not_found", f"设备不存在: {device_id}")
        valid_from = _time(data["valid_from"], "valid_from")
        valid_to = _time(data["valid_to"], "valid_to")
        if valid_to <= valid_from:
            raise ServiceError(400, "invalid_field", "valid_to 必须晚于 valid_from")
        certificate_id = data.get("certificate_id") or _new_id("cert")
        self.storage.execute(
            "INSERT INTO certificates (certificate_id, device_id, cert_ref, valid_from, valid_to, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (certificate_id, device_id, data.get("cert_ref"),
             to_iso(valid_from), to_iso(valid_to), to_iso(utcnow())),
        )
        return {"certificate_id": certificate_id, "device_id": device_id,
                "valid_from": to_iso(valid_from), "valid_to": to_iso(valid_to)}

    def create_authorization(self, data):
        _require(data, "operator_id", "device_id", "lat", "lon", "radius_m", "start_time", "end_time")
        if not self.storage.one("SELECT operator_id FROM operators WHERE operator_id = ?", (data["operator_id"],)):
            raise ServiceError(404, "operator_not_found", f"操作员不存在: {data['operator_id']}")
        if not self.storage.one("SELECT device_id FROM devices WHERE device_id = ?", (data["device_id"],)):
            raise ServiceError(404, "device_not_found", f"设备不存在: {data['device_id']}")
        start = _time(data["start_time"], "start_time")
        end = _time(data["end_time"], "end_time")
        if end <= start:
            raise ServiceError(400, "invalid_field", "end_time 必须晚于 start_time")
        authorization_id = data.get("authorization_id") or _new_id("auth")
        self.storage.execute(
            "INSERT INTO authorizations (authorization_id, operator_id, device_id, purpose, lat, lon, radius_m, "
            "start_time, end_time, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (authorization_id, data["operator_id"], data["device_id"], data.get("purpose"),
             _lat(data["lat"]), _lon(data["lon"]), float(data["radius_m"]),
             to_iso(start), to_iso(end), "active", to_iso(utcnow())),
        )
        return self.get_authorization(authorization_id)

    def get_authorization(self, authorization_id):
        row = self.storage.one("SELECT * FROM authorizations WHERE authorization_id = ?", (authorization_id,))
        if row is None:
            raise ServiceError(404, "authorization_not_found", f"授权不存在: {authorization_id}")
        return dict(row)

    def create_receiver(self, data):
        _require(data, "receiver_id")
        if self.storage.one("SELECT receiver_id FROM receivers WHERE receiver_id = ?", (data["receiver_id"],)):
            raise ServiceError(409, "duplicate_receiver", f"接收站已存在: {data['receiver_id']}")
        drift = int(data.get("clock_drift_ms") or 0)
        self.storage.execute(
            "INSERT INTO receivers (receiver_id, name, lat, lon, clock_drift_ms, created_at) VALUES (?,?,?,?,?,?)",
            (data["receiver_id"], data.get("name"),
             _lat(data["lat"]) if data.get("lat") is not None else None,
             _lon(data["lon"]) if data.get("lon") is not None else None,
             drift, to_iso(utcnow())),
        )
        return self.storage.one("SELECT * FROM receivers WHERE receiver_id = ?", (data["receiver_id"],))

    def list_receivers(self):
        return self.storage.all("SELECT * FROM receivers ORDER BY created_at")

    # ---------- 观测接入 ----------

    def ingest_observations(self, data):
        receiver_id = data.get("receiver_id")
        if not receiver_id:
            raise ServiceError(400, "missing_field", "缺少必填字段: receiver_id")
        receiver = self.storage.one("SELECT * FROM receivers WHERE receiver_id = ?", (receiver_id,))
        if receiver is None:
            raise ServiceError(404, "receiver_not_found", f"接收站未登记: {receiver_id}")
        items = data.get("observations")
        if items is None:
            items = [data.get("observation") or {"message": data.get("message"),
                                                 "received_at": data.get("received_at"),
                                                 "rssi": data.get("rssi")}]
        if not isinstance(items, list) or not items:
            raise ServiceError(400, "invalid_field", "observations 必须为非空数组")

        accepted = duplicates = linked = dup_observations = 0
        remote_ids = set()
        for item in items:
            message = (item or {}).get("message") or {}
            _require(message, "message_id", "remote_id", "timestamp", "lat", "lon")
            ts = _time(message["timestamp"], "message.timestamp")
            received_at = _time(item.get("received_at"), "received_at") if item.get("received_at") else utcnow()
            remote_id = message["remote_id"]
            remote_ids.add(remote_id)
            timing_flag = self._timing_flag(ts, received_at, receiver["clock_drift_ms"])
            cursor = self.storage.execute(
                "INSERT OR IGNORE INTO messages (remote_id, message_id, ts, lat, lon, alt, speed, heading, seq, "
                "timing_flag, first_seen_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (remote_id, message["message_id"], to_iso(ts), _lat(message["lat"]), _lon(message["lon"]),
                 message.get("alt"), message.get("speed"), message.get("heading"), message.get("seq"),
                 timing_flag, to_iso(utcnow())),
            )
            if cursor.rowcount == 1:
                accepted += 1
            else:
                duplicates += 1
            pk = self.storage.one(
                "SELECT message_pk FROM messages WHERE remote_id = ? AND message_id = ?",
                (remote_id, message["message_id"]))["message_pk"]
            cursor = self.storage.execute(
                "INSERT OR IGNORE INTO observations (message_pk, receiver_id, received_at, rssi) VALUES (?,?,?,?)",
                (pk, receiver_id, to_iso(received_at), item.get("rssi")),
            )
            if cursor.rowcount == 1:
                linked += 1
            else:
                dup_observations += 1

        new_findings, touched_cases = self._detect(sorted(remote_ids))
        return {
            "receiver_id": receiver_id,
            "accepted_messages": accepted,
            "duplicate_messages": duplicates,
            "observations_linked": linked,
            "duplicate_observations": dup_observations,
            "remote_ids": sorted(remote_ids),
            "new_findings": [f["finding_id"] for f in new_findings],
            "cases_touched": touched_cases,
        }

    def _timing_flag(self, ts, received_at, drift_ms):
        slack = timedelta(milliseconds=abs(drift_ms)) + timedelta(seconds=5)
        if ts - received_at > slack:
            return "future_dated"
        if received_at - ts > timedelta(seconds=300) + timedelta(milliseconds=abs(drift_ms)):
            return "stale"
        return None

    def run_detection(self, remote_id=None):
        if remote_id:
            targets = [remote_id]
        else:
            rows = self.storage.all("SELECT DISTINCT remote_id FROM messages")
            targets = [r["remote_id"] for r in rows]
        findings, case_ids = self._detect(targets)
        return {"remote_ids": targets,
                "new_findings": [f["finding_id"] for f in findings],
                "cases_touched": case_ids}

    def _detect(self, remote_ids):
        findings = []
        case_ids = set()
        for remote_id in remote_ids:
            for finding in rule_mod.detect_remote_id(self.storage, self.params, remote_id):
                findings.append(finding)
                case_ids.add(case_mod.ensure_case_for_finding(self.storage, self.params, finding))
        return findings, sorted(case_ids)

    # ---------- 案件 ----------

    def list_cases(self, status=None, remote_id=None, overdue=None):
        clauses, args = [], []
        if status == "active":
            clauses.append("status IN ('open','under_review','escalated')")
        elif status:
            clauses.append("status = ?")
            args.append(status)
        if remote_id:
            clauses.append("remote_id = ?")
            args.append(remote_id)
        sql = "SELECT case_id FROM cases"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY rowid"
        views = [case_mod.case_view(self.storage, r["case_id"]) for r in self.storage.all(sql, tuple(args))]
        if overdue is True:
            views = [v for v in views if v["overdue"]]
        return views

    def get_case(self, case_id):
        view = case_mod.case_view(self.storage, case_id)
        if view is None:
            raise ServiceError(404, "case_not_found", f"案件不存在: {case_id}")
        return view

    def append_case_event(self, case_id, kind, payload, actor):
        try:
            events = case_mod.append_event(self.storage, self.params, case_id, kind, payload, actor)
        except case_mod.CaseError as exc:
            raise ServiceError(exc.status, exc.code, exc.message) from None
        return {"events": events, "case": self.get_case(case_id)}

    def list_findings(self, remote_id=None):
        if remote_id:
            rows = self.storage.all(
                "SELECT * FROM findings WHERE remote_id = ? ORDER BY created_at", (remote_id,))
        else:
            rows = self.storage.all("SELECT * FROM findings ORDER BY created_at")
        return [case_mod._finding_view(r) for r in rows]

    # ---------- 身份检索视图 ----------

    def list_identities(self):
        seen = {}
        for row in self.storage.all("SELECT remote_id, MIN(ts) AS first_ts, MAX(ts) AS last_ts, "
                                    "COUNT(*) AS n FROM messages GROUP BY remote_id"):
            seen[row["remote_id"]] = {
                "remote_id": row["remote_id"], "registered": False,
                "message_count": row["n"], "first_seen": row["first_ts"], "last_seen": row["last_ts"],
            }
        for row in self.storage.all("SELECT remote_id FROM devices"):
            entry = seen.setdefault(row["remote_id"], {
                "remote_id": row["remote_id"], "message_count": 0, "first_seen": None, "last_seen": None})
            entry["registered"] = True
        return sorted(seen.values(), key=lambda e: e["remote_id"])

    def identity_view(self, remote_id, role):
        device = self.storage.one("SELECT * FROM devices WHERE remote_id = ?", (remote_id,))
        messages = self.storage.all(
            "SELECT * FROM messages WHERE remote_id = ? ORDER BY ts, message_id", (remote_id,))
        if device is None and not messages:
            raise ServiceError(404, "identity_not_found", f"未检索到广播身份: {remote_id}")
        for message in messages:
            message["ts"] = parse_iso(message["ts"])

        operator = None
        certificates = []
        authorizations = []
        if device:
            op_row = self.storage.one("SELECT * FROM operators WHERE operator_id = ?", (device["operator_id"],))
            operator = _operator_view(op_row, role) if op_row else None
            certificates = self.storage.all(
                "SELECT * FROM certificates WHERE device_id = ? ORDER BY valid_from", (device["device_id"],))
            authorizations = self.storage.all(
                "SELECT * FROM authorizations WHERE device_id = ? ORDER BY start_time", (device["device_id"],))

        tracklets, _ = build_tracklets(messages, self.params)
        findings = self.list_findings(remote_id)
        case_rows = self.storage.all(
            "SELECT case_id FROM cases WHERE remote_id = ? ORDER BY rowid", (remote_id,))
        case_views = [case_mod.case_view(self.storage, r["case_id"]) for r in case_rows]

        return {
            "remote_id": remote_id,
            "registered": device is not None,
            "device": self._device_view(device) if device else None,
            "operator": operator,
            "identity_continuity": self._continuity(messages, certificates, device),
            "authorizations": [self._authorization_view(a, messages) for a in authorizations],
            "broadcast_summary": self._broadcast_summary(messages),
            "tracklets": [tracklet_summary(t) for t in tracklets],
            "conflict_windows": _conflict_windows(findings),
            "associations": self._associations(device, operator, certificates, authorizations, messages),
            "detections": [{**f, "parameters": _rule_params(self.params, f["rule_id"])} for f in findings],
            "cases": case_views,
        }

    def _continuity(self, messages, certificates, device):
        if device is None:
            return {"continuous": False, "uncovered_broadcasts": len(messages),
                    "note": "广播身份未登记，无证书链"}
        uncovered = 0
        for message in messages:
            if not any(parse_iso(c["valid_from"]) <= message["ts"] <= parse_iso(c["valid_to"])
                       for c in certificates):
                uncovered += 1
        continuous = uncovered == 0 and bool(messages)
        note = ("全部广播时间均有证书覆盖，轮换期间身份保持连续" if continuous
                else f"有 {uncovered} 条广播时间不在任何证书有效期内")
        return {
            "continuous": continuous,
            "uncovered_broadcasts": uncovered,
            "certificate_windows": [
                {"certificate_id": c["certificate_id"], "valid_from": c["valid_from"], "valid_to": c["valid_to"]}
                for c in certificates
            ],
            "note": note,
        }

    def _authorization_view(self, auth, messages):
        start, end = parse_iso(auth["start_time"]), parse_iso(auth["end_time"])
        inside = 0
        for message in messages:
            if (start <= message["ts"] <= end
                    and haversine_m(auth["lat"], auth["lon"], message["lat"], message["lon"]) <= auth["radius_m"]):
                inside += 1
        return {
            "authorization_id": auth["authorization_id"],
            "purpose": auth["purpose"],
            "area": {"lat": auth["lat"], "lon": auth["lon"], "radius_m": auth["radius_m"]},
            "start_time": auth["start_time"],
            "end_time": auth["end_time"],
            "status": auth["status"],
            "observed_points_inside": inside,
            "observed_points_total": len(messages),
        }

    def _broadcast_summary(self, messages):
        receivers = self.storage.all(
            "SELECT DISTINCT r.receiver_id, r.name, r.clock_drift_ms FROM observations o "
            "JOIN receivers r ON r.receiver_id = o.receiver_id "
            "JOIN messages m ON m.message_pk = o.message_pk WHERE m.remote_id = ?",
            (messages[0]["remote_id"],) if messages else ("",))
        return {
            "message_count": len(messages),
            "first_seen": to_iso(messages[0]["ts"]) if messages else None,
            "last_seen": to_iso(messages[-1]["ts"]) if messages else None,
            "receivers": receivers,
        }

    def _associations(self, device, operator, certificates, authorizations, messages):
        associations = []
        if device:
            associations.append({
                "type": "device", "ref": device["device_id"],
                "basis": f"广播身份 {device['remote_id']} 在设备注册表中唯一匹配序列号 {device['serial']}",
            })
        if operator:
            associations.append({
                "type": "operator", "ref": operator["operator_id"],
                "basis": "注册设备所属操作员",
            })
        for cert in certificates:
            covered = sum(
                1 for m in messages
                if parse_iso(cert["valid_from"]) <= m["ts"] <= parse_iso(cert["valid_to"]))
            associations.append({
                "type": "certificate", "ref": cert["certificate_id"],
                "basis": f"证书有效期 {cert['valid_from']}~{cert['valid_to']} 覆盖 {covered}/{len(messages)} 条广播时间",
            })
        for auth in authorizations:
            start, end = parse_iso(auth["start_time"]), parse_iso(auth["end_time"])
            inside = sum(
                1 for m in messages
                if start <= m["ts"] <= end
                and haversine_m(auth["lat"], auth["lon"], m["lat"], m["lon"]) <= auth["radius_m"])
            associations.append({
                "type": "authorization", "ref": auth["authorization_id"],
                "basis": f"{inside}/{len(messages)} 个广播点位于授权空域与时段内（{auth.get('purpose') or '未注明用途'}）",
            })
        receiver_rows = self.storage.all(
            "SELECT r.receiver_id, r.clock_drift_ms, COUNT(*) AS n FROM observations o "
            "JOIN receivers r ON r.receiver_id = o.receiver_id "
            "JOIN messages m ON m.message_pk = o.message_pk WHERE m.remote_id = ? "
            "GROUP BY r.receiver_id",
            (messages[0]["remote_id"],) if messages else ("",))
        for row in receiver_rows:
            associations.append({
                "type": "receiver", "ref": row["receiver_id"],
                "basis": f"接收站观测到 {row['n']} 条广播，时钟漂移 {row['clock_drift_ms']}ms",
            })
        return associations


_PII_ROLE = next(iter(PII_VISIBLE_ROLES))


def _operator_view(row, role):
    contact = json.loads(row["contact_json"] or "{}")
    if role not in PII_VISIBLE_ROLES:
        contact = {key: "***" for key in contact}
    return {
        "operator_id": row["operator_id"],
        "name": row["name"],
        "organization": row["organization"],
        "contact": contact,
        "contact_masked": role not in PII_VISIBLE_ROLES,
        "created_at": row["created_at"],
    }


def _conflict_windows(findings):
    """把冲突类发现的时间窗合并，回答“冲突发生在哪段时间”。"""
    windows = []
    for finding in findings:
        if finding["rule_id"] not in rule_mod.CONFLICT_RULES:
            continue
        if not finding["window_start"] or not finding["window_end"]:
            continue
        start, end = parse_iso(finding["window_start"]), parse_iso(finding["window_end"])
        for window in windows:
            if start <= window["end"] and end >= window["start"]:
                window["start"] = min(window["start"], start)
                window["end"] = max(window["end"], end)
                window["rule_ids"].add(finding["rule_id"])
                window["finding_ids"].append(finding["finding_id"])
                break
        else:
            windows.append({"start": start, "end": end,
                            "rule_ids": {finding["rule_id"]}, "finding_ids": [finding["finding_id"]]})
    windows.sort(key=lambda w: w["start"])
    return [
        {"start": to_iso(w["start"]), "end": to_iso(w["end"]),
         "rule_ids": sorted(w["rule_ids"]), "finding_ids": w["finding_ids"]}
        for w in windows
    ]


def _rule_params(params, rule_id):
    keys = {
        "duplicate_identity": ("duplicate_distance_m", "duplicate_window_s"),
        "impossible_speed": ("max_plausible_speed_mps",),
        "position_jump": ("position_jump_distance_m", "position_jump_time_s"),
        "expired_certificate": (),
        "unregistered_identity": (),
    }.get(rule_id, ())
    return {key: params[key] for key in keys}
