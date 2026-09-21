"""运行配置：检测参数、角色与复核时限。均可通过环境变量覆盖。"""

import os

DEFAULT_PARAMS = {
    # 运动学可行性：超过该速度的连续两点视为不可达
    "max_plausible_speed_mps": float(os.environ.get("RID_MAX_SPEED_MPS", "75.0")),
    # 位置跳变：极短时间窗内位移超过阈值
    "position_jump_distance_m": float(os.environ.get("RID_JUMP_DISTANCE_M", "500.0")),
    "position_jump_time_s": float(os.environ.get("RID_JUMP_TIME_S", "2.0")),
    # 重复身份：同一时间窗内空间分离超过阈值
    "duplicate_distance_m": float(os.environ.get("RID_DUP_DISTANCE_M", "1000.0")),
    "duplicate_window_s": float(os.environ.get("RID_DUP_WINDOW_S", "60.0")),
    "simultaneous_distance_m": float(os.environ.get("RID_SIM_DISTANCE_M", "100.0")),
    # 轨迹分段：超过该间隔视为新航迹段
    "track_gap_s": float(os.environ.get("RID_TRACK_GAP_S", "120.0")),
    # 证书类发现的时间窗归并间隔
    "cert_window_group_gap_s": float(os.environ.get("RID_CERT_GROUP_GAP_S", "300.0")),
    # 接收站时钟漂移显著性阈值：超过则下调证据可信度（不构成定性依据）
    "clock_drift_significant_ms": int(os.environ.get("RID_DRIFT_SIGNIFICANT_MS", "1000")),
    # 复核时限
    "review_sla_hours": float(os.environ.get("RID_REVIEW_SLA_HOURS", "24.0")),
    "escalated_review_sla_hours": float(os.environ.get("RID_ESCALATED_SLA_HOURS", "4.0")),
}

ROLE_DISPATCHER = "放行员"
ROLE_MAINTAINER = "机务人员"
ROLE_REGULATOR = "监管人员"
ROLE_INVESTIGATOR = "调查员"
ROLE_READONLY = "只读用户"

ROLES = [ROLE_DISPATCHER, ROLE_MAINTAINER, ROLE_REGULATOR, ROLE_INVESTIGATOR, ROLE_READONLY]
DEFAULT_ROLE = ROLE_READONLY

# 个人联系方式仅调查角色可见
PII_VISIBLE_ROLES = {ROLE_INVESTIGATOR}
