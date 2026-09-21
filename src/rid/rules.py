"""异常检测规则：重复身份、不可达速度、位置跳变、过期证书、未登记身份。

原则：
- 只基于按源时间排序、去重后的报文序列取证，乱序/重复报文不产生虚假轨迹；
- 接收站时钟漂移只下调证据可信度，不直接形成定性；
- 发现按 dedupe_key 幂等落库，重复扫描不产生重复发现。
"""

import json
import uuid

from .geo import haversine_m
from .timeutil import parse_iso, to_iso, utcnow
from .tracks import build_tracklets

RULE_NAMES = {
    "duplicate_identity": "重复身份冲突",
    "impossible_speed": "不可达速度",
    "position_jump": "位置跳变",
    "expired_certificate": "过期证书广播",
    "unregistered_identity": "未登记广播身份",
}

BASE_CONFIDENCE = {
    "duplicate_identity": 0.9,
    "impossible_speed": 0.85,
    "position_jump": 0.9,
    "expired_certificate": 0.95,
    "unregistered_identity": 0.9,
}

# 冲突类规则：用于身份视图中合并展示冲突时间段
CONFLICT_RULES = ("duplicate_identity", "impossible_speed", "position_jump")


def _new_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _group_by_gap(messages, gap_s):
    """按时间间隔把报文分组，用于证书类发现的时间窗归并。"""
    groups = []
    current = []
    for message in messages:
        if current and (message["ts"] - current[-1]["ts"]).total_seconds() > gap_s:
            groups.append(current)
            current = []
        current.append(message)
    if current:
        groups.append(current)
    return groups


def _receivers_for(storage, message_pks):
    if not message_pks:
        return []
    placeholders = ",".join("?" for _ in message_pks)
    return storage.all(
        "SELECT DISTINCT r.receiver_id, r.clock_drift_ms "
        "FROM observations o JOIN receivers r ON r.receiver_id = o.receiver_id "
        f"WHERE o.message_pk IN ({placeholders})",
        tuple(message_pks),
    )


def _confidence(storage, rule_id, messages, params):
    """计算证据可信度。时钟漂移与时间异常只降可信度，不构成定性依据。"""
    confidence = BASE_CONFIDENCE[rule_id]
    factors = []
    receivers = _receivers_for(storage, [m["message_pk"] for m in messages])
    drifts = [abs(r["clock_drift_ms"]) for r in receivers]
    max_drift = max(drifts) if drifts else 0
    if max_drift >= params["clock_drift_significant_ms"]:
        confidence *= 0.7
        factors.append(
            f"接收站时钟漂移最大 {max_drift}ms，时间一致性证据可信度下调；"
            "时钟漂移仅降低证据可信度，不直接构成定性依据"
        )
    if any(m.get("timing_flag") for m in messages):
        confidence *= 0.8
        factors.append("部分报文接收时间与广播源时间偏差异常，可信度下调")
    return round(max(confidence, 0.05), 2), factors


def _make_finding(storage, params, rule_id, remote_id, window, details, messages, dedupe_key):
    confidence, factors = _confidence(storage, rule_id, messages, params)
    return {
        "finding_id": _new_id("find"),
        "dedupe_key": dedupe_key,
        "rule_id": rule_id,
        "remote_id": remote_id,
        "window_start": to_iso(window[0]) if window else None,
        "window_end": to_iso(window[1]) if window else None,
        "confidence": confidence,
        "confidence_factors": factors,
        "details": details,
    }


def _detect_infeasible(transitions, remote_id, params):
    """不可达速度与位置跳变：来自航迹分段时记录的不可行点对。"""
    findings = []
    for tr in transitions:
        if tr["kind"] != "infeasible":
            continue
        prev, cur = tr["prev"], tr["cur"]
        window = (prev["ts"], cur["ts"])
        base = {
            "from": {"lat": prev["lat"], "lon": prev["lon"], "ts": to_iso(prev["ts"])},
            "to": {"lat": cur["lat"], "lon": cur["lon"], "ts": to_iso(cur["ts"])},
            "distance_m": round(tr["distance_m"], 1),
            "dt_s": round(tr["dt_s"], 3),
            "implied_speed_mps": round(tr["implied_speed_mps"], 1),
            "message_ids": [prev["message_id"], cur["message_id"]],
        }
        if tr["dt_s"] <= params["position_jump_time_s"] and tr["distance_m"] >= params["position_jump_distance_m"]:
            rule_id = "position_jump"
        else:
            rule_id = "impossible_speed"
        key = f"{rule_id}|{remote_id}|{prev['message_pk']}|{cur['message_pk']}"
        findings.append((rule_id, window, base, [prev, cur], key))
    return findings


def _detect_duplicate_identity(messages, remote_id, params):
    """重复身份：同一时间窗内空间上不可能属于同一目标的报文集合。"""
    conflicted = []
    max_separation = 0.0
    samples = []
    for i, first in enumerate(messages):
        for second in messages[i + 1:]:
            dt_s = (second["ts"] - first["ts"]).total_seconds()
            if dt_s > params["duplicate_window_s"]:
                break
            dist_m = haversine_m(first["lat"], first["lon"], second["lat"], second["lon"])
            if dist_m > params["duplicate_distance_m"]:
                conflicted.append((first, second))
                if dist_m > max_separation:
                    max_separation = dist_m
                    samples = [first, second]
    if not conflicted:
        return []
    involved = {}
    for pair in conflicted:
        for message in pair:
            involved[message["message_pk"]] = message
    grouped = _group_by_gap(sorted(involved.values(), key=lambda m: (m["ts"], m["message_id"])),
                            params["duplicate_window_s"] * 2)
    findings = []
    for group in grouped:
        window = (group[0]["ts"], group[-1]["ts"])
        details = {
            "max_separation_m": round(max_separation, 1),
            "message_count": len(group),
            "sample_points": [
                {"lat": m["lat"], "lon": m["lon"], "ts": to_iso(m["ts"]), "message_id": m["message_id"]}
                for m in samples
            ],
            "message_ids": [m["message_id"] for m in group],
        }
        key = f"duplicate_identity|{remote_id}|{to_iso(window[0])}|{to_iso(window[1])}|{len(group)}"
        findings.append(("duplicate_identity", window, details, group, key))
    return findings


def _detect_certificate(messages, remote_id, device, certificates, params):
    """过期证书 / 未登记身份。证书轮换期只要有任一证书覆盖广播时间即视为连续。"""
    if device is None:
        grouped = _group_by_gap(messages, params["cert_window_group_gap_s"])
        findings = []
        for group in grouped:
            window = (group[0]["ts"], group[-1]["ts"])
            details = {"message_count": len(group), "reason": "广播身份未在设备注册表中登记"}
            key = f"unregistered_identity|{remote_id}|{to_iso(window[0])}|{to_iso(window[1])}|{len(group)}"
            findings.append(("unregistered_identity", window, details, group, key))
        return findings
    uncovered = []
    for message in messages:
        if not any(parse_iso(c["valid_from"]) <= message["ts"] <= parse_iso(c["valid_to"]) for c in certificates):
            uncovered.append(message)
    findings = []
    for group in _group_by_gap(uncovered, params["cert_window_group_gap_s"]):
        window = (group[0]["ts"], group[-1]["ts"])
        details = {
            "message_count": len(group),
            "device_id": device["device_id"],
            "certificate_windows": [
                {"certificate_id": c["certificate_id"], "valid_from": c["valid_from"], "valid_to": c["valid_to"]}
                for c in certificates
            ],
        }
        key = f"expired_certificate|{remote_id}|{to_iso(window[0])}|{to_iso(window[1])}|{len(group)}"
        findings.append(("expired_certificate", window, details, group, key))
    return findings


def detect_remote_id(storage, params, remote_id):
    """对单个广播身份运行全部规则，返回本次新产生的发现（幂等）。"""
    rows = storage.all(
        "SELECT * FROM messages WHERE remote_id = ? ORDER BY ts, message_id", (remote_id,)
    )
    if not rows:
        return []
    messages = []
    for row in rows:
        message = dict(row)
        message["ts"] = parse_iso(row["ts"])
        messages.append(message)

    device = storage.one("SELECT * FROM devices WHERE remote_id = ?", (remote_id,))
    certificates = []
    if device:
        certificates = storage.all(
            "SELECT * FROM certificates WHERE device_id = ? ORDER BY valid_from", (device["device_id"],)
        )

    _, transitions = build_tracklets(messages, params)
    candidates = []
    candidates += _detect_infeasible(transitions, remote_id, params)
    candidates += _detect_duplicate_identity(messages, remote_id, params)
    candidates += _detect_certificate(messages, remote_id, device, certificates, params)

    new_findings = []
    for rule_id, window, details, evidence_messages, dedupe_key in candidates:
        finding = _make_finding(storage, params, rule_id, remote_id, window, details,
                                evidence_messages, dedupe_key)
        cursor = storage.execute(
            "INSERT OR IGNORE INTO findings "
            "(finding_id, dedupe_key, rule_id, remote_id, window_start, window_end, "
            " confidence, confidence_factors_json, details_json, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                finding["finding_id"], finding["dedupe_key"], finding["rule_id"], finding["remote_id"],
                finding["window_start"], finding["window_end"], finding["confidence"],
                _json_dumps(finding["confidence_factors"]), _json_dumps(finding["details"]),
                to_iso(utcnow()),
            ),
        )
        if cursor.rowcount == 1:
            new_findings.append(finding)
    return new_findings


def _json_dumps(value):
    return json.dumps(value, ensure_ascii=False)
