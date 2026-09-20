"""SQLite 持久化。

所有需要落盘的数据都写入运行时配置的 db 路径；案件状态变化通过
case_events 追加记录，cases 表只是当前状态的物化，重启后未结案件与
复核时限照常推进。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any, Optional

from .models import CaseStatus, Observation, iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS operators (
    operator_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT,
    email TEXT,
    id_number TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    operator_id TEXT NOT NULL REFERENCES operators(operator_id),
    serial_number TEXT NOT NULL,
    model TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS certificates (
    cert_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    remote_id TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT NOT NULL,
    replaces_cert_id TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cert_remote ON certificates(remote_id);
CREATE INDEX IF NOT EXISTS idx_cert_device ON certificates(device_id);
CREATE TABLE IF NOT EXISTS authorizations (
    auth_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    area TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_device ON authorizations(device_id);
CREATE TABLE IF NOT EXISTS receivers (
    receiver_id TEXT PRIMARY KEY,
    name TEXT,
    lat REAL,
    lon REAL,
    clock_uncertainty_ms REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    obs_id TEXT PRIMARY KEY,
    remote_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    device_time TEXT,
    lat REAL NOT NULL,
    lon REAL NOT NULL,
    alt REAL,
    speed_mps REAL,
    cert_id TEXT,
    receiver_id TEXT NOT NULL REFERENCES receivers(receiver_id),
    received_at TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    UNIQUE(remote_id, receiver_id, seq, content_hash)
);
CREATE INDEX IF NOT EXISTS idx_obs_remote ON observations(remote_id);
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    remote_id TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    opened_at TEXT NOT NULL,
    review_due_at TEXT NOT NULL,
    merged_into TEXT,
    closed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_cases_remote ON cases(remote_id);
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    rule TEXT NOT NULL,
    remote_id TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    confidence REAL NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_findings_remote ON findings(remote_id);
CREATE TABLE IF NOT EXISTS case_events (
    event_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_case ON case_events(case_id);
"""


class Storage:
    def __init__(self, db_path: str):
        directory = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(directory, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock, self._conn:
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- 登记 ----

    def upsert_operator(self, row: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO operators (operator_id, name, phone, email, id_number, created_at)
                   VALUES (:operator_id, :name, :phone, :email, :id_number, :created_at)
                   ON CONFLICT(operator_id) DO UPDATE SET
                     name=excluded.name, phone=excluded.phone,
                     email=excluded.email, id_number=excluded.id_number""",
                row,
            )

    def get_operator(self, operator_id: str) -> Optional[dict[str, Any]]:
        return self._fetchone("SELECT * FROM operators WHERE operator_id=?", (operator_id,))

    def upsert_device(self, row: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO devices (device_id, operator_id, serial_number, model, created_at)
                   VALUES (:device_id, :operator_id, :serial_number, :model, :created_at)
                   ON CONFLICT(device_id) DO UPDATE SET
                     operator_id=excluded.operator_id,
                     serial_number=excluded.serial_number, model=excluded.model""",
                row,
            )

    def get_device(self, device_id: str) -> Optional[dict[str, Any]]:
        return self._fetchone("SELECT * FROM devices WHERE device_id=?", (device_id,))

    def upsert_certificate(self, row: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO certificates
                     (cert_id, device_id, remote_id, valid_from, valid_to,
                      replaces_cert_id, created_at)
                   VALUES (:cert_id, :device_id, :remote_id, :valid_from, :valid_to,
                           :replaces_cert_id, :created_at)
                   ON CONFLICT(cert_id) DO UPDATE SET
                     device_id=excluded.device_id, remote_id=excluded.remote_id,
                     valid_from=excluded.valid_from, valid_to=excluded.valid_to,
                     replaces_cert_id=excluded.replaces_cert_id""",
                row,
            )

    def get_certificate(self, cert_id: str) -> Optional[dict[str, Any]]:
        return self._fetchone("SELECT * FROM certificates WHERE cert_id=?", (cert_id,))

    def certificates_by_remote_id(self, remote_id: str) -> list[dict[str, Any]]:
        return self._fetchall(
            "SELECT * FROM certificates WHERE remote_id=? ORDER BY valid_from", (remote_id,)
        )

    def certificates_by_device(self, device_id: str) -> list[dict[str, Any]]:
        return self._fetchall(
            "SELECT * FROM certificates WHERE device_id=? ORDER BY valid_from", (device_id,)
        )

    def upsert_authorization(self, row: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO authorizations
                     (auth_id, device_id, area, start_time, end_time, created_at)
                   VALUES (:auth_id, :device_id, :area, :start_time, :end_time, :created_at)
                   ON CONFLICT(auth_id) DO UPDATE SET
                     device_id=excluded.device_id, area=excluded.area,
                     start_time=excluded.start_time, end_time=excluded.end_time""",
                row,
            )

    def authorizations_by_device(self, device_id: str) -> list[dict[str, Any]]:
        return self._fetchall(
            "SELECT * FROM authorizations WHERE device_id=? ORDER BY start_time", (device_id,)
        )

    def upsert_receiver(self, row: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO receivers
                     (receiver_id, name, lat, lon, clock_uncertainty_ms, created_at)
                   VALUES (:receiver_id, :name, :lat, :lon, :clock_uncertainty_ms, :created_at)
                   ON CONFLICT(receiver_id) DO UPDATE SET
                     name=excluded.name, lat=excluded.lat, lon=excluded.lon,
                     clock_uncertainty_ms=excluded.clock_uncertainty_ms""",
                row,
            )

    def get_receiver(self, receiver_id: str) -> Optional[dict[str, Any]]:
        return self._fetchone("SELECT * FROM receivers WHERE receiver_id=?", (receiver_id,))

    def receivers_all(self) -> list[dict[str, Any]]:
        return self._fetchall("SELECT * FROM receivers", ())

    # ---- 观测 ----

    def insert_observation(self, obs: Observation) -> bool:
        """幂等写入；已存在相同 (remote_id, receiver_id, seq, content_hash) 返回 False。"""
        row = {
            "obs_id": obs.obs_id,
            "remote_id": obs.remote_id,
            "seq": obs.seq,
            "device_time": iso(obs.device_time) if obs.device_time else None,
            "lat": obs.lat,
            "lon": obs.lon,
            "alt": obs.alt,
            "speed_mps": obs.speed_mps,
            "cert_id": obs.cert_id,
            "receiver_id": obs.receiver_id,
            "received_at": iso(obs.received_at),
            "content_hash": obs.content_hash,
            "ingested_at": iso(obs.ingested_at),
        }
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """INSERT OR IGNORE INTO observations
                     (obs_id, remote_id, seq, device_time, lat, lon, alt, speed_mps,
                      cert_id, receiver_id, received_at, content_hash, ingested_at)
                   VALUES (:obs_id, :remote_id, :seq, :device_time, :lat, :lon, :alt,
                           :speed_mps, :cert_id, :receiver_id, :received_at,
                           :content_hash, :ingested_at)""",
                row,
            )
            return cursor.rowcount > 0

    def observations_by_remote_id(self, remote_id: str, limit: int = 2000) -> list[Observation]:
        rows = self._fetchall(
            """SELECT * FROM observations WHERE remote_id=?
               ORDER BY received_at DESC LIMIT ?""",
            (remote_id, limit),
        )
        return [self._row_to_observation(r) for r in rows]

    def count_observations(self, remote_id: str) -> int:
        row = self._fetchone(
            "SELECT COUNT(*) AS n FROM observations WHERE remote_id=?", (remote_id,)
        )
        return int(row["n"]) if row else 0

    # ---- 案件 ----

    def insert_case(self, row: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO cases
                     (case_id, remote_id, status, severity, opened_at, review_due_at,
                      merged_into, closed_at)
                   VALUES (:case_id, :remote_id, :status, :severity, :opened_at,
                           :review_due_at, :merged_into, :closed_at)""",
                row,
            )

    def update_case(self, case_id: str, **fields: Any) -> None:
        allowed = {"status", "severity", "review_due_at", "merged_into", "closed_at"}
        assignments = {k: v for k, v in fields.items() if k in allowed}
        if not assignments:
            return
        clause = ", ".join(f"{k}=?" for k in assignments)
        with self._lock, self._conn:
            self._conn.execute(
                f"UPDATE cases SET {clause} WHERE case_id=?",
                (*assignments.values(), case_id),
            )

    def get_case(self, case_id: str) -> Optional[dict[str, Any]]:
        return self._fetchone("SELECT * FROM cases WHERE case_id=?", (case_id,))

    def cases_by_remote_id(self, remote_id: str) -> list[dict[str, Any]]:
        return self._fetchall(
            "SELECT * FROM cases WHERE remote_id=? ORDER BY opened_at", (remote_id,)
        )

    def open_cases_by_remote_id(self, remote_id: str) -> list[dict[str, Any]]:
        terminal = tuple(s.value for s in CaseStatus if s in (
            CaseStatus.RESOLVED, CaseStatus.EXCLUDED, CaseStatus.MERGED))
        return self._fetchall(
            f"""SELECT * FROM cases WHERE remote_id=?
                AND status NOT IN ({",".join("?" for _ in terminal)})
                ORDER BY opened_at DESC""",
            (remote_id, *terminal),
        )

    def list_cases(self, status: Optional[str] = None) -> list[dict[str, Any]]:
        if status:
            return self._fetchall(
                "SELECT * FROM cases WHERE status=? ORDER BY opened_at DESC", (status,)
            )
        return self._fetchall("SELECT * FROM cases ORDER BY opened_at DESC", ())

    # ---- 证据与事件（追加式） ----

    def insert_finding(self, row: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO findings
                     (fingerprint, case_id, rule, remote_id, window_start, window_end,
                      confidence, payload, created_at)
                   VALUES (:fingerprint, :case_id, :rule, :remote_id, :window_start,
                           :window_end, :confidence, :payload, :created_at)""",
                row,
            )

    def finding_exists(self, fingerprint: str) -> bool:
        row = self._fetchone(
            "SELECT 1 AS x FROM findings WHERE fingerprint=?", (fingerprint,)
        )
        return row is not None

    def findings_by_case(self, case_id: str) -> list[dict[str, Any]]:
        return self._fetchall(
            "SELECT * FROM findings WHERE case_id=? ORDER BY created_at", (case_id,)
        )

    def findings_by_remote_id(self, remote_id: str) -> list[dict[str, Any]]:
        return self._fetchall(
            "SELECT * FROM findings WHERE remote_id=? ORDER BY window_start", (remote_id,)
        )

    def append_event(self, row: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO case_events (event_id, case_id, ts, actor, kind, payload)
                   VALUES (:event_id, :case_id, :ts, :actor, :kind, :payload)""",
                row,
            )

    def events_by_case(self, case_id: str) -> list[dict[str, Any]]:
        return self._fetchall(
            "SELECT * FROM case_events WHERE case_id=? ORDER BY ts, event_id", (case_id,)
        )

    def count_events(self, case_id: str) -> int:
        row = self._fetchone(
            "SELECT COUNT(*) AS n FROM case_events WHERE case_id=?", (case_id,)
        )
        return int(row["n"]) if row else 0

    # ---- 内部 ----

    def _fetchone(self, sql: str, params: tuple) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def _fetchall(self, sql: str, params: tuple) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def _row_to_observation(row: dict[str, Any]) -> Observation:
        from .models import parse_ts

        return Observation(
            obs_id=row["obs_id"],
            remote_id=row["remote_id"],
            seq=int(row["seq"]),
            device_time=parse_ts(row["device_time"]) if row["device_time"] else None,
            lat=float(row["lat"]),
            lon=float(row["lon"]),
            alt=row["alt"],
            speed_mps=row["speed_mps"],
            cert_id=row["cert_id"],
            receiver_id=row["receiver_id"],
            received_at=parse_ts(row["received_at"]),
            content_hash=row["content_hash"],
            ingested_at=parse_ts(row["ingested_at"]),
        )


def dumps_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)
