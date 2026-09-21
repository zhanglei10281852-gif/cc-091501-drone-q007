"""时间工具：统一使用带时区的 ISO 8601，内部一律转为 UTC。"""

from datetime import datetime, timezone


def parse_iso(value, field="timestamp"):
    """解析带时区的 ISO 8601 字符串为 UTC datetime，拒绝无时区输入。"""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} 必须为带时区的 ISO 8601 字符串")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{field} 不是合法的 ISO 8601 时间: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} 必须包含时区信息")
    return parsed.astimezone(timezone.utc)


def to_iso(moment):
    """把 datetime 格式化为 UTC ISO 8601（Z 结尾）。"""
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def utcnow():
    return datetime.now(timezone.utc)
