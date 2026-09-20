"""领域模型、常量与通用工具。

时间统一使用带时区的 ISO 8601 字符串，内部一律转换为 UTC 的
datetime 处理；存储层落盘的也是 UTC ISO 字符串。
"""
from __future__ import annotations

import hashlib
import json
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class ValidationError(Exception):
    """输入校验失败（HTTP 400）。"""


class NotFoundError(Exception):
    """资源不存在（HTTP 404）。"""


class ForbiddenError(Exception):
    """角色无权执行该操作（HTTP 403）。"""


class ConflictError(Exception):
    """与当前状态冲突，如对终态案件再次处置（HTTP 409）。"""


class Role(str, Enum):
    REGULATOR = "regulator"        # 监管人员
    INVESTIGATOR = "investigator"  # 调查员
    READONLY = "readonly"          # 只读用户
    SYSTEM = "system"              # 系统/接收站接入


# 个人联系方式仅调查角色可见
PII_ROLES = {Role.INVESTIGATOR}
# 案件处置（合并、排除、升级、分诊、结案）仅调查员
DISPOSITION_ROLES = {Role.INVESTIGATOR}
# 人工追加证据：调查员与监管人员
EVIDENCE_ROLES = {Role.INVESTIGATOR, Role.REGULATOR}
# 广播观测摄入：系统接入或内部角色
INGEST_ROLES = {Role.SYSTEM, Role.INVESTIGATOR, Role.REGULATOR}
# 登记类写操作
REGISTER_ROLES = {Role.REGULATOR, Role.INVESTIGATOR, Role.SYSTEM}


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    EXCLUDED = "EXCLUDED"
    MERGED = "MERGED"


TERMINAL_STATUSES = {CaseStatus.RESOLVED, CaseStatus.EXCLUDED, CaseStatus.MERGED}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}
# 各严重度的复核时限（小时），案件打开时物化 review_due_at，重启后继续推进
DEFAULT_SLA_HOURS = {"high": 4.0, "medium": 24.0, "low": 72.0}

# 检测规则与参数。随案件证据一起记录版本与参数快照，复核时可追溯采用的规则。
RULE_PARAMS: dict[str, dict[str, Any]] = {
    "duplicate_identity": {
        "version": "1.0",
        "min_cluster_points": 2,      # 构成独立发射源的最小轨迹点数
        "separation_margin_m": 200.0, # 簇间最小显著间距
        "max_link_gap_s": 120.0,      # 报告间隔超过该值即失去轨迹连续性
    },
    "unreachable_speed": {
        "version": "1.0",
        "max_speed_mps": 60.0,        # 城市无人机最大合理速度，轨迹切簇同用
    },
    "position_jump": {
        "version": "1.0",
        "hard_limit_mps": 340.0,      # 隐含速度超过则按位置跳变处理
    },
    "expired_certificate": {
        "version": "1.0",
    },
}

RULE_BASE_SEVERITY = {
    "duplicate_identity": "high",
    "unreachable_speed": "medium",
    "position_jump": "medium",
    "expired_certificate": "medium",
}

# 同一广播身份、同一规则的相邻发现归并到同一案件的时间间隔
CASE_MERGE_GAP_SECONDS = 600.0

# 接收站时钟不确定度分档（毫秒）：漂移只降低证据可信度，不参与定性
CLOCK_GOOD_MS = 200.0
CLOCK_DEGRADED_MS = 2000.0

# 同一 (机载时间, 序号) 的多站观测，位置差异超过该值视为矛盾观测并拆分
CORROBORATION_RADIUS_M = 500.0


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def parse_ts(value: Any, field_name: str = "timestamp") -> datetime:
    """解析带时区的 ISO 8601 时间；缺时区或格式非法即拒绝。"""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field_name} 必须是带时区的 ISO 8601 字符串")
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError as exc:
        raise ValidationError(f"{field_name} 不是合法的 ISO 8601 时间: {value!r}") from exc
    if dt.tzinfo is None:
        raise ValidationError(f"{field_name} 必须携带时区信息")
    return dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def receiver_confidence(clock_uncertainty_ms: float) -> float:
    """接收站时钟漂移对应的证据置信度。漂移只降信，不产生或消除结论。"""
    if clock_uncertainty_ms <= CLOCK_GOOD_MS:
        return 1.0
    if clock_uncertainty_ms <= CLOCK_DEGRADED_MS:
        return 0.8
    return 0.5


def content_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class Observation:
    """一条接收站上报的广播观测。device_time 可空：机载时间缺失时只能
    退化为接收时间，证据置信度随之降低。"""

    obs_id: str
    remote_id: str
    seq: int
    device_time: Optional[datetime]
    lat: float
    lon: float
    alt: Optional[float]
    speed_mps: Optional[float]
    cert_id: Optional[str]
    receiver_id: str
    received_at: datetime
    content_hash: str
    ingested_at: datetime


@dataclass
class Finding:
    """一次检测命中。window 为冲突/异常发生的时间段。"""

    rule: str
    remote_id: str
    window_start: datetime
    window_end: datetime
    confidence: float
    limiting_factors: list[str]
    details: dict[str, Any]
    observation_ids: list[str] = field(default_factory=list)

    def fingerprint(self) -> str:
        key = json.dumps(
            {
                "rule": self.rule,
                "remote_id": self.remote_id,
                "window": [iso(self.window_start), iso(self.window_end)],
                "obs": sorted(self.observation_ids),
            },
            sort_keys=True,
        )
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]

    def to_payload(self) -> dict[str, Any]:
        params = RULE_PARAMS.get(self.rule, {})
        return {
            "rule": self.rule,
            "rule_version": params.get("version"),
            "rule_params": params,
            "remote_id": self.remote_id,
            "window_start": iso(self.window_start),
            "window_end": iso(self.window_end),
            "confidence": self.confidence,
            "limiting_factors": list(self.limiting_factors),
            "details": self.details,
            "observation_ids": list(self.observation_ids),
        }
