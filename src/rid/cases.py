"""人工复核案件：合并、排除、升级等一切处置均以追加证据事件完成，
事件流是唯一事实来源，cases 表上的状态只是其投影。"""

import json
import uuid
from datetime import timedelta

from .timeutil import parse_iso, to_iso, utcnow
from .rules import RULE_NAMES

ACTIVE_STATUSES = ("open", "under_review", "escalated")
TERMINAL_STATUSES = ("excluded", "resolved", "merged")

SEVERITY_BY_RULE = {
    "duplicate_identity": "high",
    "impossible_speed": "medium",
    "position_jump": "medium",
    "expired_certificate": "medium",
    "unregistered_identity": "medium",
}

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

EVENT_KINDS = (
    "detection",   # 检测发现追加为证据
    "comment",     # 调查备注
    "review",      # 开始人工复核
    "escalate",    # 升级严重度并收紧复核时限
    "exclude",     # 排除（误报），须附理由
    "resolve",     # 办结
    "reopen",      # 重新打开
    "merge",       # 吸收另一案件
    "merged_into", # 被另一案件吸收（系统自动写入）
)


class CaseError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _new_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def ensure_case_for_finding(storage, params, finding, now=None):
    """发现落案：同身份同规则已有未结案件则追加证据，否则新建案件。"""
    now = now or utcnow()
    existing = storage.one(
        "SELECT * FROM cases WHERE remote_id = ? AND rule_id = ? AND status IN ('open','under_review','escalated') "
        "ORDER BY rowid LIMIT 1",
        (finding["remote_id"], finding["rule_id"]),
    )
    if existing:
        case_id = existing["case_id"]
    else:
        case_id = _new_id("case")
        title = f"{RULE_NAMES.get(finding['rule_id'], finding['rule_id'])}：{finding['remote_id']}"
        due = now + timedelta(hours=params["review_sla_hours"])
        storage.execute(
            "INSERT INTO cases (case_id, remote_id, rule_id, title, status, severity, created_at, review_due_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (case_id, finding["remote_id"], finding["rule_id"], title, "open",
             SEVERITY_BY_RULE.get(finding["rule_id"], "medium"), to_iso(now), to_iso(due)),
        )
    storage.execute(
        "INSERT OR IGNORE INTO case_findings (case_id, finding_id) VALUES (?,?)",
        (case_id, finding["finding_id"]),
    )
    _insert_event(storage, case_id, "detection", {
        "finding_id": finding["finding_id"],
        "rule_id": finding["rule_id"],
        "window_start": finding["window_start"],
        "window_end": finding["window_end"],
        "confidence": finding["confidence"],
        "confidence_factors": finding["confidence_factors"],
    }, actor="system", now=now)
    return case_id


def _insert_event(storage, case_id, kind, payload, actor, now=None):
    now = now or utcnow()
    event = {
        "event_id": _new_id("ev"),
        "case_id": case_id,
        "ts": to_iso(now),
        "actor": actor,
        "kind": kind,
        "payload": payload,
    }
    storage.execute(
        "INSERT INTO case_events (event_id, case_id, ts, actor, kind, payload_json) VALUES (?,?,?,?,?,?)",
        (event["event_id"], case_id, event["ts"], actor, kind,
         json.dumps(payload, ensure_ascii=False)),
    )
    return event


def append_event(storage, params, case_id, kind, payload, actor, now=None):
    """追加证据事件并同步状态投影。所有处置动作都经此入口，不可篡改历史。"""
    now = now or utcnow()
    payload = payload or {}
    case = storage.one("SELECT * FROM cases WHERE case_id = ?", (case_id,))
    if case is None:
        raise CaseError(404, "case_not_found", f"案件不存在: {case_id}")
    if kind not in EVENT_KINDS:
        raise CaseError(400, "unknown_event_kind", f"不支持的事件类型: {kind}")
    if case["status"] == "merged":
        raise CaseError(409, "case_merged", "案件已被合并，不可再处置")
    if kind in ("review", "escalate", "exclude", "resolve", "merge") and case["status"] not in ACTIVE_STATUSES:
        raise CaseError(409, "case_not_active", f"案件状态为 {case['status']}，不能执行 {kind}")
    if kind == "reopen" and case["status"] not in ("excluded", "resolved"):
        raise CaseError(409, "case_not_reopenable", "仅已排除或已办结的案件可以重新打开")

    events = []
    if kind == "escalate":
        severity = payload.get("severity")
        if severity not in SEVERITY_ORDER:
            current = SEVERITY_ORDER.index(case["severity"])
            severity = SEVERITY_ORDER[min(current + 1, len(SEVERITY_ORDER) - 1)]
        due = now + timedelta(hours=params["escalated_review_sla_hours"])
        storage.execute(
            "UPDATE cases SET status = 'escalated', severity = ?, review_due_at = ? WHERE case_id = ?",
            (severity, to_iso(due), case_id),
        )
        events.append(_insert_event(storage, case_id, kind, {**payload, "severity": severity}, actor, now))
    elif kind == "review":
        storage.execute("UPDATE cases SET status = 'under_review' WHERE case_id = ?", (case_id,))
        events.append(_insert_event(storage, case_id, kind, payload, actor, now))
    elif kind == "exclude":
        if not payload.get("reason"):
            raise CaseError(400, "reason_required", "排除案件必须附理由")
        storage.execute("UPDATE cases SET status = 'excluded' WHERE case_id = ?", (case_id,))
        events.append(_insert_event(storage, case_id, kind, payload, actor, now))
    elif kind == "resolve":
        storage.execute("UPDATE cases SET status = 'resolved' WHERE case_id = ?", (case_id,))
        events.append(_insert_event(storage, case_id, kind, payload, actor, now))
    elif kind == "reopen":
        due = now + timedelta(hours=params["review_sla_hours"])
        storage.execute(
            "UPDATE cases SET status = 'under_review', review_due_at = ? WHERE case_id = ?",
            (to_iso(due), case_id),
        )
        events.append(_insert_event(storage, case_id, kind, payload, actor, now))
    elif kind == "merge":
        other_id = payload.get("absorb_case_id")
        if not other_id or other_id == case_id:
            raise CaseError(400, "invalid_merge", "必须指定不同的 absorb_case_id")
        other = storage.one("SELECT * FROM cases WHERE case_id = ?", (other_id,))
        if other is None:
            raise CaseError(404, "case_not_found", f"被合并案件不存在: {other_id}")
        if other["status"] not in ACTIVE_STATUSES:
            raise CaseError(409, "case_not_active", f"被合并案件状态为 {other['status']}，不能合并")
        storage.execute("UPDATE case_findings SET case_id = ? WHERE case_id = ?", (case_id, other_id))
        storage.execute(
            "UPDATE cases SET status = 'merged', merged_into = ? WHERE case_id = ?", (case_id, other_id),
        )
        events.append(_insert_event(storage, case_id, "merge",
                                    {"absorbed_case_id": other_id, "reason": payload.get("reason")}, actor, now))
        events.append(_insert_event(storage, other_id, "merged_into",
                                    {"into_case_id": case_id, "reason": payload.get("reason")}, actor, now))
    else:  # comment / detection
        events.append(_insert_event(storage, case_id, kind, payload, actor, now))
    return events


def case_view(storage, case_id, now=None):
    now = now or utcnow()
    case = storage.one("SELECT * FROM cases WHERE case_id = ?", (case_id,))
    if case is None:
        return None
    findings = storage.all(
        "SELECT f.* FROM findings f JOIN case_findings cf ON cf.finding_id = f.finding_id "
        "WHERE cf.case_id = ? ORDER BY f.rowid",
        (case_id,),
    )
    events = storage.all(
        "SELECT * FROM case_events WHERE case_id = ? ORDER BY rowid", (case_id,),
    )
    due = parse_iso(case["review_due_at"])
    active = case["status"] in ACTIVE_STATUSES
    return {
        "case_id": case["case_id"],
        "remote_id": case["remote_id"],
        "rule_id": case["rule_id"],
        "rule_name": RULE_NAMES.get(case["rule_id"], case["rule_id"]),
        "title": case["title"],
        "status": case["status"],
        "severity": case["severity"],
        "created_at": case["created_at"],
        "review_due_at": case["review_due_at"],
        "overdue": bool(active and due < now),
        "remaining_seconds": int((due - now).total_seconds()) if active else None,
        "merged_into": case["merged_into"],
        "findings": [_finding_view(f) for f in findings],
        "progress": [
            {"event_id": e["event_id"], "ts": e["ts"], "actor": e["actor"], "kind": e["kind"],
             "payload": json.loads(e["payload_json"])}
            for e in events
        ],
    }


def _finding_view(row):
    return {
        "finding_id": row["finding_id"],
        "rule_id": row["rule_id"],
        "rule_name": RULE_NAMES.get(row["rule_id"], row["rule_id"]),
        "remote_id": row["remote_id"],
        "window_start": row["window_start"],
        "window_end": row["window_end"],
        "confidence": row["confidence"],
        "confidence_factors": json.loads(row["confidence_factors_json"]),
        "details": json.loads(row["details_json"]),
        "created_at": row["created_at"],
    }
