import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from rid.models import Observation  # noqa: E402
from rid.tracking import build_track, cluster_points, consecutive_breaks  # noqa: E402

BASE = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


def make_obs(remote_id, seq, t_s, lat, lon, receiver="st-1", cert=None):
    return Observation(
        obs_id=f"obs-{receiver}-{seq}-{t_s}-{lat}-{lon}",
        remote_id=remote_id,
        seq=seq,
        device_time=BASE + timedelta(seconds=t_s),
        lat=lat,
        lon=lon,
        alt=None,
        speed_mps=None,
        cert_id=cert,
        receiver_id=receiver,
        received_at=BASE + timedelta(seconds=t_s + 1),
        content_hash="x",
        ingested_at=BASE,
    )


class BuildTrackTest(unittest.TestCase):
    def test_out_of_order_input_is_sorted(self):
        obs = [
            make_obs("R", 2, 40, 31.0, 121.0),
            make_obs("R", 0, 0, 31.0, 121.0),
            make_obs("R", 1, 20, 31.0, 121.0),
        ]
        track = build_track(obs)
        self.assertEqual([p.seq for p in track], [0, 1, 2])

    def test_duplicate_broadcast_from_two_receivers_merges(self):
        obs = [
            make_obs("R", 0, 0, 31.0, 121.0, receiver="st-1"),
            make_obs("R", 0, 0, 31.0, 121.0, receiver="st-2"),
        ]
        track = build_track(obs)
        self.assertEqual(len(track), 1)
        self.assertEqual(sorted(track[0].receiver_ids), ["st-1", "st-2"])
        self.assertEqual(len(track[0].observation_ids), 2)

    def test_contradictory_same_seq_is_split(self):
        # 同一序号同一机载时刻出现在相距 10 公里的两地：不能合并为一个点
        obs = [
            make_obs("R", 0, 0, 31.0, 121.0, receiver="st-1"),
            make_obs("R", 0, 0, 31.0, 121.1, receiver="st-2"),
        ]
        track = build_track(obs)
        self.assertEqual(len(track), 2)

    def test_missing_device_time_excluded(self):
        obs = make_obs("R", 0, 0, 31.0, 121.0)
        obs.device_time = None
        self.assertEqual(build_track([obs]), [])


class ClusterTest(unittest.TestCase):
    def test_interleaved_sources_form_two_clusters(self):
        obs = []
        for i in range(3):
            obs.append(make_obs("R", i, i * 20, 31.0 + i * 0.0001, 121.0, "st-1"))
            obs.append(make_obs("R", i, i * 20 + 5, 31.0 + i * 0.0001, 121.1, "st-2"))
        points = build_track(obs)
        clusters = cluster_points(points, 60.0)
        sizes = sorted(len(c) for c in clusters)
        self.assertEqual(sizes, [3, 3])

    def test_normal_track_single_cluster_no_breaks(self):
        obs = [make_obs("R", i, i * 20, 31.0 + i * 0.001, 121.0) for i in range(6)]
        points = build_track(obs)
        clusters = cluster_points(points, 60.0)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(consecutive_breaks(points, 60.0), [])


if __name__ == "__main__":
    unittest.main()
