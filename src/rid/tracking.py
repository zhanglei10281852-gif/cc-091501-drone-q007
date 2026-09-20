"""轨迹重建。

只按机载时间 (device_time, seq) 排序与去重，与报文到达顺序无关：
乱序或重复报文不会拼出虚假轨迹。同一 (device_time, seq) 被多个接收站
收到时合并为一个轨迹点（多站佐证）；若这些观测位置相互矛盾，则拆分为
独立轨迹点——同一编号同一时刻出现在两地本身就是异常信号。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .models import CORROBORATION_RADIUS_M, Observation, haversine_m


@dataclass
class TrackPoint:
    device_time: datetime
    seq: int
    lat: float
    lon: float
    alt: Optional[float]
    observation_ids: list[str] = field(default_factory=list)
    receiver_ids: list[str] = field(default_factory=list)


def _split_contradictory(group: list[Observation]) -> list[list[Observation]]:
    """同一 (device_time, seq) 的观测按位置连通性拆分：相距超过
    CORROBORATION_RADIUS_M 的观测不属于同一广播源。"""
    clusters: list[list[Observation]] = []
    for obs in group:
        placed = False
        for cluster in clusters:
            anchor = cluster[0]
            if haversine_m(anchor.lat, anchor.lon, obs.lat, obs.lon) <= CORROBORATION_RADIUS_M:
                cluster.append(obs)
                placed = True
                break
        if not placed:
            clusters.append([obs])
    return clusters


def build_track(observations: list[Observation]) -> list[TrackPoint]:
    """由观测重建有序轨迹点。缺机载时间的观测不参与轨迹（其时间基准
    不可信，只在证书检查等场景按低置信度使用）。"""
    groups: dict[tuple[datetime, int], list[Observation]] = {}
    for obs in observations:
        if obs.device_time is None:
            continue
        groups.setdefault((obs.device_time, obs.seq), []).append(obs)

    points: list[TrackPoint] = []
    for (dt, seq), group in groups.items():
        for cluster in _split_contradictory(group):
            first = cluster[0]
            points.append(
                TrackPoint(
                    device_time=dt,
                    seq=seq,
                    lat=first.lat,
                    lon=first.lon,
                    alt=first.alt,
                    observation_ids=[o.obs_id for o in cluster],
                    receiver_ids=sorted({o.receiver_id for o in cluster}),
                )
            )
    points.sort(key=lambda p: (p.device_time, p.seq, p.lat, p.lon))
    return points


def implied_speed_mps(prev: TrackPoint, nxt: TrackPoint) -> float:
    dt = (nxt.device_time - prev.device_time).total_seconds()
    dist = haversine_m(prev.lat, prev.lon, nxt.lat, nxt.lon)
    if dt <= 0:
        return 0.0 if dist < 1e-6 else float("inf")
    return dist / dt


def cluster_points(
    points: list[TrackPoint],
    max_speed_mps: float,
    max_link_gap_s: float = 120.0,
) -> list[list[TrackPoint]]:
    """时空可达性聚类（并查集）：两点时间间隔不超过 max_link_gap_s 且
    隐含速度不超过 max_speed_mps 才连通。不能只按编号把观测归并为一条
    轨迹——两个发射源广播同一编号时，其观测在时间上交错，靠可达性才能
    分成两个各自连续的簇。报告间隔过长时连续性不可假定，不能跨间隔
    桥接两个空间簇。"""
    parent = list(range(len(points)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in range(len(points)):
        for j in range(i + 1, len(points)):
            dt = (points[j].device_time - points[i].device_time).total_seconds()
            if dt > max_link_gap_s:
                break  # 点列按时间有序，之后的点间隔更大
            if implied_speed_mps(points[i], points[j]) <= max_speed_mps:
                ri, rj = find(i), find(j)
                if ri != rj:
                    parent[ri] = rj

    groups: dict[int, list[TrackPoint]] = {}
    for i, point in enumerate(points):
        groups.setdefault(find(i), []).append(point)
    return list(groups.values())


def consecutive_breaks(
    points: list[TrackPoint], max_speed_mps: float
) -> list[tuple[TrackPoint, TrackPoint, float]]:
    """时间有序点列中相邻点隐含速度超过 max_speed_mps 的断点。"""
    breaks = []
    for prev, nxt in zip(points, points[1:]):
        speed = implied_speed_mps(prev, nxt)
        if speed > max_speed_mps:
            breaks.append((prev, nxt, speed))
    return breaks
