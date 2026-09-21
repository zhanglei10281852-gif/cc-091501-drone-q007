"""航迹构建：报文先按广播源时间排序、按 (remote_id, message_id) 去重，
再按运动学可行性分段。乱序或重复报文不会拼出虚假轨迹。"""

from .geo import haversine_m
from .timeutil import to_iso


def build_tracklets(messages, params):
    """把同一 remote_id 的报文（已按 ts 升序）切成运动学可行的航迹段。

    返回 (tracklets, transitions)：
    - tracklets: [{"messages": [...], "start": dt, "end": dt}]
    - transitions: 不可行或同时刻冲突的相邻点对，供检测规则取证
    """
    tracklets = []
    transitions = []
    current = []

    def close():
        if current:
            tracklets.append({"messages": list(current), "start": current[0]["ts"], "end": current[-1]["ts"]})

    for message in messages:
        if not current:
            current = [message]
            continue
        prev = current[-1]
        dt_s = (message["ts"] - prev["ts"]).total_seconds()
        dist_m = haversine_m(prev["lat"], prev["lon"], message["lat"], message["lon"])
        if dt_s <= 0:
            # 同一时刻（或时间戳倒挂）的重复位置：不连接，也不截断航迹
            if dist_m > params["simultaneous_distance_m"]:
                transitions.append({
                    "kind": "simultaneous_conflict",
                    "prev": prev,
                    "cur": message,
                    "dt_s": dt_s,
                    "distance_m": dist_m,
                })
                close()
                current = [message]
            continue
        if dt_s > params["track_gap_s"]:
            close()
            current = [message]
            continue
        implied_speed = dist_m / dt_s
        if implied_speed > params["max_plausible_speed_mps"]:
            transitions.append({
                "kind": "infeasible",
                "prev": prev,
                "cur": message,
                "dt_s": dt_s,
                "distance_m": dist_m,
                "implied_speed_mps": implied_speed,
            })
            close()
            current = [message]
            continue
        current.append(message)
    close()
    return tracklets, transitions


def tracklet_summary(tracklet):
    messages = tracklet["messages"]
    seq_gaps = 0
    for prev, cur in zip(messages, messages[1:]):
        if prev.get("seq") is not None and cur.get("seq") is not None and cur["seq"] != prev["seq"] + 1:
            seq_gaps += 1
    return {
        "start": to_iso(tracklet["start"]),
        "end": to_iso(tracklet["end"]),
        "point_count": len(messages),
        "seq_gaps": seq_gaps,
        "message_ids": [m["message_id"] for m in messages],
    }
