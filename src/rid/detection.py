"""异常检测规则：重复身份、不可达速度、位置跳变、过期证书。

所有检测只产出 Finding（线索），一律进入人工复核案件，系统不作最终
定性。接收站时钟漂移只通过置信度体现：漂移越大，证据置信度越低，
但不会凭空产生或消除结论。
"""
from __future__ import annotations

from typing import Any, Optional

from .models import (
    Finding,
    Observation,
    RULE_PARAMS,
    haversine_m,
    iso,
    parse_ts,
    receiver_confidence,
)
from .tracking import (
    TrackPoint,
    build_track,
    cluster_points,
    consecutive_breaks,
)


def _observation_confidence(
    obs: Observation, receivers: dict[str, dict[str, Any]]
) -> tuple[float, list[str]]:
    conf = 1.0
    factors: list[str] = []
    receiver = receivers.get(obs.receiver_id)
    if receiver is not None:
        rc = receiver_confidence(float(receiver["clock_uncertainty_ms"]))
        if rc < 1.0:
            conf = min(conf, rc)
            factors.append("receiver_clock_drift")
    if obs.device_time is None:
        # 缺机载时间，只能依赖接收站时钟，可信度减半
        conf *= 0.5
        factors.append("device_time_missing")
    return conf, factors


def _aggregate_confidence(
    observations: list[Observation], receivers: dict[str, dict[str, Any]]
) -> tuple[float, list[str]]:
    conf = 1.0
    factors: set[str] = set()
    for obs in observations:
        obs_conf, obs_factors = _observation_confidence(obs, receivers)
        conf = min(conf, obs_conf)
        factors.update(obs_factors)
    return round(conf, 3), sorted(factors)


def _point_summary(point: TrackPoint) -> dict[str, Any]:
    return {
        "device_time": iso(point.device_time),
        "seq": point.seq,
        "lat": point.lat,
        "lon": point.lon,
        "receiver_ids": list(point.receiver_ids),
    }


def detect_anomalies(
    remote_id: str,
    observations: list[Observation],
    certificates: dict[str, dict[str, Any]],
    receivers: dict[str, dict[str, Any]],
    rule_params: Optional[dict[str, dict[str, Any]]] = None,
) -> list[Finding]:
    params = rule_params or RULE_PARAMS
    findings: list[Finding] = []
    findings.extend(_detect_certificate(remote_id, observations, certificates, receivers))
    findings.extend(_detect_track(remote_id, observations, receivers, params))
    return findings


def _detect_certificate(
    remote_id: str,
    observations: list[Observation],
    certificates: dict[str, dict[str, Any]],
    receivers: dict[str, dict[str, Any]],
) -> list[Finding]:
    """广播时间（机载时间优先，缺失时退化接收时间）落在证书有效期外。"""
    groups: dict[tuple[str, str], list[tuple[Any, Observation]]] = {}
    for obs in observations:
        if not obs.cert_id:
            continue
        cert = certificates.get(obs.cert_id)
        if cert is None:
            continue
        moment = obs.device_time or obs.received_at
        valid_from = parse_ts(cert["valid_from"], "valid_from")
        valid_to = parse_ts(cert["valid_to"], "valid_to")
        if valid_from <= moment <= valid_to:
            continue
        reason = "cert_expired" if moment > valid_to else "cert_not_yet_valid"
        groups.setdefault((obs.cert_id, reason), []).append((moment, obs))

    findings: list[Finding] = []
    for (cert_id, reason), items in groups.items():
        items.sort(key=lambda item: item[0])
        obs_list = [obs for _, obs in items]
        conf, factors = _aggregate_confidence(obs_list, receivers)
        findings.append(
            Finding(
                rule="expired_certificate",
                remote_id=remote_id,
                window_start=items[0][0],
                window_end=items[-1][0],
                confidence=conf,
                limiting_factors=factors,
                details={
                    "reason": reason,
                    "cert_id": cert_id,
                    "cert_valid_from": certificates[cert_id]["valid_from"],
                    "cert_valid_to": certificates[cert_id]["valid_to"],
                    "observation_count": len(obs_list),
                },
                observation_ids=[obs.obs_id for obs in obs_list],
            )
        )
    return findings


def _cluster_span(cluster: list[TrackPoint]):
    return cluster[0].device_time, cluster[-1].device_time


def _spans_overlap(a: list[TrackPoint], b: list[TrackPoint]) -> bool:
    a_start, a_end = _cluster_span(a)
    b_start, b_end = _cluster_span(b)
    return a_start <= b_end and b_start <= a_end


def _separation_m(a: list[TrackPoint], b: list[TrackPoint]) -> float:
    return max(
        haversine_m(pa.lat, pa.lon, pb.lat, pb.lon) for pa in a for pb in b
    )


def _detect_track(
    remote_id: str,
    observations: list[Observation],
    receivers: dict[str, dict[str, Any]],
    params: dict[str, dict[str, Any]],
) -> list[Finding]:
    points = build_track(observations)
    if len(points) < 2:
        return []

    obs_by_id = {obs.obs_id: obs for obs in observations}
    max_speed = float(params["unreachable_speed"]["max_speed_mps"])
    hard_limit = float(params["position_jump"]["hard_limit_mps"])
    min_cluster = int(params["duplicate_identity"]["min_cluster_points"])
    margin = float(params["duplicate_identity"]["separation_margin_m"])
    max_link_gap = float(params["duplicate_identity"]["max_link_gap_s"])

    def obs_of(point: TrackPoint) -> list[Observation]:
        return [obs_by_id[oid] for oid in point.observation_ids if oid in obs_by_id]

    findings: list[Finding] = []

    # 各自连续的簇；只有时间跨度相互重叠且空间显著分离的簇对，才说明
    # 同一编号在同一时段出现在不可同时到达的两地（重复身份）。时间错开
    # 的簇属于单目标移动过快，按不可达速度/位置跳变处理。
    clusters = cluster_points(points, max_speed, max_link_gap)
    substantial = [c for c in clusters if len(c) >= min_cluster]
    duplicate_point_ids: set[int] = set()
    if len(substantial) >= 2:
        involved: set[int] = set()
        for i in range(len(substantial)):
            for j in range(i + 1, len(substantial)):
                if _spans_overlap(substantial[i], substantial[j]) and (
                    _separation_m(substantial[i], substantial[j]) > margin
                ):
                    involved.add(i)
                    involved.add(j)
        if involved:
            dup_clusters = [substantial[k] for k in sorted(involved)]
            summaries = []
            for cluster in dup_clusters:
                start, end = _cluster_span(cluster)
                lat = sum(p.lat for p in cluster) / len(cluster)
                lon = sum(p.lon for p in cluster) / len(cluster)
                summaries.append(
                    {
                        "center": {"lat": round(lat, 6), "lon": round(lon, 6)},
                        "point_count": len(cluster),
                        "start": iso(start),
                        "end": iso(end),
                        "receiver_ids": sorted(
                            {r for p in cluster for r in p.receiver_ids}
                        ),
                    }
                )
                for p in cluster:
                    duplicate_point_ids.add(id(p))
            max_separation = max(
                _separation_m(dup_clusters[i], dup_clusters[j])
                for i in range(len(dup_clusters))
                for j in range(i + 1, len(dup_clusters))
            )
            involved_obs = [
                obs for cluster in dup_clusters for p in cluster for obs in obs_of(p)
            ]
            conf, factors = _aggregate_confidence(involved_obs, receivers)
            findings.append(
                Finding(
                    rule="duplicate_identity",
                    remote_id=remote_id,
                    window_start=min(_cluster_span(c)[0] for c in dup_clusters),
                    window_end=max(_cluster_span(c)[1] for c in dup_clusters),
                    confidence=conf,
                    limiting_factors=factors,
                    details={
                        "cluster_count": len(dup_clusters),
                        "max_separation_m": round(max_separation, 1),
                        "clusters": summaries,
                    },
                    observation_ids=[obs.obs_id for obs in involved_obs],
                )
            )

    # 相邻断点：已被重复身份解释的点对不再重复报案
    for prev, nxt, speed in consecutive_breaks(points, max_speed):
        if id(prev) in duplicate_point_ids and id(nxt) in duplicate_point_ids:
            continue
        involved_obs = obs_of(prev) + obs_of(nxt)
        conf, factors = _aggregate_confidence(involved_obs, receivers)
        rule = "position_jump" if speed > hard_limit else "unreachable_speed"
        findings.append(
            Finding(
                rule=rule,
                remote_id=remote_id,
                window_start=prev.device_time,
                window_end=nxt.device_time,
                confidence=conf,
                limiting_factors=factors,
                details={
                    "implied_speed_mps": None if speed == float("inf") else round(speed, 2),
                    "distance_m": round(
                        haversine_m(prev.lat, prev.lon, nxt.lat, nxt.lon), 1
                    ),
                    "from": _point_summary(prev),
                    "to": _point_summary(nxt),
                },
                observation_ids=[obs.obs_id for obs in involved_obs],
            )
        )
    return findings
