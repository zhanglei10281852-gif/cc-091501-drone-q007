"""SQLite 持久化层：所有实体与追加式案件证据落盘，服务重启后状态不丢失。"""

import os
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS operators (
  operator_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  organization TEXT,
  contact_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  serial TEXT NOT NULL UNIQUE,
  model TEXT,
  operator_id TEXT NOT NULL REFERENCES operators(operator_id),
  remote_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS certificates (
  certificate_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  cert_ref TEXT,
  valid_from TEXT NOT NULL,
  valid_to TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authorizations (
  authorization_id TEXT PRIMARY KEY,
  operator_id TEXT NOT NULL REFERENCES operators(operator_id),
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  purpose TEXT,
  lat REAL NOT NULL,
  lon REAL NOT NULL,
  radius_m REAL NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS receivers (
  receiver_id TEXT PRIMARY KEY,
  name TEXT,
  lat REAL,
  lon REAL,
  clock_drift_ms INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  message_pk INTEGER PRIMARY KEY AUTOINCREMENT,
  remote_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  lat REAL NOT NULL,
  lon REAL NOT NULL,
  alt REAL,
  speed REAL,
  heading REAL,
  seq INTEGER,
  timing_flag TEXT,
  first_seen_at TEXT NOT NULL,
  UNIQUE (remote_id, message_id)
);
CREATE TABLE IF NOT EXISTS observations (
  observation_pk INTEGER PRIMARY KEY AUTOINCREMENT,
  message_pk INTEGER NOT NULL REFERENCES messages(message_pk),
  receiver_id TEXT NOT NULL REFERENCES receivers(receiver_id),
  received_at TEXT NOT NULL,
  rssi REAL,
  UNIQUE (message_pk, receiver_id)
);
CREATE TABLE IF NOT EXISTS findings (
  finding_id TEXT PRIMARY KEY,
  dedupe_key TEXT NOT NULL UNIQUE,
  rule_id TEXT NOT NULL,
  remote_id TEXT NOT NULL,
  window_start TEXT,
  window_end TEXT,
  confidence REAL NOT NULL,
  confidence_factors_json TEXT NOT NULL DEFAULT '[]',
  details_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY,
  remote_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  created_at TEXT NOT NULL,
  review_due_at TEXT NOT NULL,
  merged_into TEXT
);
CREATE TABLE IF NOT EXISTS case_findings (
  case_id TEXT NOT NULL REFERENCES cases(case_id),
  finding_id TEXT NOT NULL UNIQUE REFERENCES findings(finding_id),
  PRIMARY KEY (case_id, finding_id)
);
CREATE TABLE IF NOT EXISTS case_events (
  event_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(case_id),
  ts TEXT NOT NULL,
  actor TEXT,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_messages_remote_ts ON messages(remote_id, ts);
CREATE INDEX IF NOT EXISTS idx_findings_remote ON findings(remote_id);
CREATE INDEX IF NOT EXISTS idx_cases_remote ON cases(remote_id);
CREATE INDEX IF NOT EXISTS idx_events_case ON case_events(case_id);
"""


def default_db_path():
    """落盘位置由运行时配置指定：RID_DB_PATH 优先，其次 DATA_DIR，默认 ./.data/rid.db。"""
    explicit = os.environ.get("RID_DB_PATH")
    if explicit:
        return explicit
    data_dir = os.environ.get("DATA_DIR", ".data")
    return os.path.join(data_dir, "rid.db")


class Storage:
    """线程安全的薄封装：所有访问经同一把可重入锁串行化。"""

    def __init__(self, path):
        self.path = path
        if path != ":memory:":
            directory = os.path.dirname(os.path.abspath(path))
            if directory:
                os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    def close(self):
        with self._lock:
            self._conn.close()

    def execute(self, sql, args=()):
        with self._lock:
            cursor = self._conn.execute(sql, args)
            self._conn.commit()
            return cursor

    def one(self, sql, args=()):
        with self._lock:
            row = self._conn.execute(sql, args).fetchone()
            return dict(row) if row is not None else None

    def all(self, sql, args=()):
        with self._lock:
            return [dict(row) for row in self._conn.execute(sql, args).fetchall()]
