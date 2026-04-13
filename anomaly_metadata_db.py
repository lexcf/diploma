"""
Логирование метаданных обнаруженных аномалий в SQLite.

В таблицу сохраняются только агрегированные признаки и служебные поля.
Сырые пакеты и их payload в БД не записываются.
"""

import sqlite3
import time
from typing import Optional, Dict


class AnomalyMetadataLogger:
    """SQLite-логгер метаданных аномалий."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS anomaly_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    interface TEXT,
                    model_path TEXT,
                    window_start REAL,
                    window_end REAL,
                    duration REAL,
                    anomaly_score REAL,
                    score_threshold REAL,
                    packet_count INTEGER,
                    packets_per_second REAL,
                    unique_src_ip INTEGER,
                    unique_dst_ip INTEGER,
                    unique_src_port INTEGER,
                    unique_dst_port INTEGER,
                    avg_length REAL,
                    proto_tcp INTEGER,
                    proto_udp INTEGER,
                    proto_icmp INTEGER
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_anomaly_events_created_at "
                "ON anomaly_events(created_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_anomaly_events_window_end "
                "ON anomaly_events(window_end)"
            )

    def log_anomaly(
        self,
        result: Dict,
        interface: str,
        model_path: str,
        score_threshold: Optional[float],
    ):
        """Сохраняет запись о срабатывании аномалии (только метаданные)."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO anomaly_events (
                    created_at,
                    interface,
                    model_path,
                    window_start,
                    window_end,
                    duration,
                    anomaly_score,
                    score_threshold,
                    packet_count,
                    packets_per_second,
                    unique_src_ip,
                    unique_dst_ip,
                    unique_src_port,
                    unique_dst_port,
                    avg_length,
                    proto_tcp,
                    proto_udp,
                    proto_icmp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(time.time()),
                    interface,
                    model_path,
                    self._safe_float(result.get("window_start")),
                    self._safe_float(result.get("window_end")),
                    self._safe_float(result.get("duration")),
                    self._safe_float(result.get("anomaly_score")),
                    score_threshold,
                    self._safe_int(result.get("packet_count")),
                    self._safe_float(result.get("packets_per_second")),
                    self._safe_int(result.get("unique_src_ip")),
                    self._safe_int(result.get("unique_dst_ip")),
                    self._safe_int(result.get("unique_src_port")),
                    self._safe_int(result.get("unique_dst_port")),
                    self._safe_float(result.get("avg_length")),
                    self._safe_int(result.get("proto_tcp")),
                    self._safe_int(result.get("proto_udp")),
                    self._safe_int(result.get("proto_icmp")),
                ),
            )

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _safe_float(value) -> Optional[float]:
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
