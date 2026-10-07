import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from antivirus.config.settings import SCAN_DB_PATH


class ScanRepository:
    """Stores simple scan-history records in SQLite."""

    def __init__(self, db_path: str | None = None):
        self.db_path = str(db_path or SCAN_DB_PATH)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _initialize(self) -> None:
        connection = sqlite3.connect(self.db_path)
        try:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    file_count INTEGER NOT NULL,
                    threats_found INTEGER NOT NULL,
                    clean_files INTEGER NOT NULL,
                    error_files INTEGER NOT NULL,
                    status TEXT NOT NULL
                )
                """)
            existing_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(scan_history)")
            }
            migrations = {
                "target": "TEXT NOT NULL DEFAULT ''",
                "scan_type": "TEXT NOT NULL DEFAULT 'custom'",
                "duration": "REAL NOT NULL DEFAULT 0",
                "threats": "TEXT NOT NULL DEFAULT '[]'",
                "skipped_files": "INTEGER NOT NULL DEFAULT 0",
                "warnings": "TEXT NOT NULL DEFAULT '[]'",
                "report": "TEXT NOT NULL DEFAULT '{}'",
            }
            for column, declaration in migrations.items():
                if column not in existing_columns:
                    connection.execute(
                        f"ALTER TABLE scan_history ADD COLUMN {column} {declaration}"
                    )
            connection.commit()
        finally:
            connection.close()

    def record_scan(
        self,
        file_count: int,
        threats_found: int,
        clean_files: int,
        error_files: int,
        status: str,
        started_at: Optional[str] = None,
        completed_at: Optional[str] = None,
        target: str = "",
        scan_type: str = "custom",
        duration: float = 0.0,
        threats: Optional[List[Dict[str, Any]]] = None,
        skipped_files: int = 0,
        warnings: list[str] | None = None,
        report: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        import datetime

        started_value = started_at or datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(timespec="seconds")
        completed_value = completed_at or started_value

        connection = sqlite3.connect(self.db_path)
        try:
            cursor = connection.execute(
                """
                INSERT INTO scan_history (
                    started_at,
                    completed_at,
                    file_count,
                    threats_found,
                    clean_files,
                    error_files,
                    status,
                    target,
                    scan_type,
                    duration,
                    threats, skipped_files, warnings, report
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    started_value,
                    completed_value,
                    file_count,
                    threats_found,
                    clean_files,
                    error_files,
                    status,
                    target,
                    scan_type,
                    duration,
                    json.dumps(threats or []),
                    skipped_files,
                    json.dumps(warnings or []),
                    json.dumps(report or {}),
                ),
            )
            connection.commit()
            row_id = cursor.lastrowid
        finally:
            connection.close()

        return {
            "id": row_id,
            "started_at": started_value,
            "completed_at": completed_value,
            "file_count": file_count,
            "threats_found": threats_found,
            "clean_files": clean_files,
            "error_files": error_files,
            "status": status,
            "target": target,
            "scan_type": scan_type,
            "duration": duration,
            "threats": threats or [],
            "skipped_files": skipped_files,
            "warnings": warnings or [],
            "report": report or {},
        }

    def get_recent_scans(self, limit: int | None = 10) -> List[Dict[str, Any]]:
        connection = sqlite3.connect(self.db_path)
        try:
            rows = connection.execute(
                """
                SELECT id, started_at, completed_at, file_count, threats_found,
                       clean_files, error_files, status, target, scan_type, duration, threats,
                       skipped_files, warnings, report
                FROM scan_history
                ORDER BY id DESC
                LIMIT ?
                """,
                (-1 if limit is None else max(0, int(limit)),),
            ).fetchall()
        finally:
            connection.close()

        records = []
        for row in rows:
            try:
                threats = json.loads(row[11] or "[]")
            except (json.JSONDecodeError, TypeError):
                threats = []
            records.append(
                {
                    "id": row[0],
                    "started_at": row[1],
                    "completed_at": row[2],
                    "file_count": row[3],
                    "threats_found": row[4],
                    "clean_files": row[5],
                    "error_files": row[6],
                    "status": row[7],
                    "target": row[8],
                    "scan_type": row[9],
                    "duration": row[10],
                    "threats": threats,
                    "skipped_files": row[12],
                    "warnings": self._read_list(row[13]),
                    "report": self._read_dict(row[14]),
                }
            )
        return records

    @staticmethod
    def _read_list(value):
        try:
            parsed = json.loads(value or "[]")
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []

    @staticmethod
    def _read_dict(value):
        try:
            parsed = json.loads(value or "{}")
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    def clear_history(self) -> int:
        """Delete scan-history rows and return the number removed."""

        connection = sqlite3.connect(self.db_path)
        try:
            removed = connection.execute("DELETE FROM scan_history").rowcount
            connection.commit()
            return int(removed)
        finally:
            connection.close()

    def delete_scans(self, record_ids: list[int]) -> int:
        """Remove selected records by stable IDs in one transaction."""
        if any(
            type(record_id) is not int or record_id <= 0 for record_id in record_ids
        ):
            raise ValueError("History record IDs must be positive integers.")
        selected = sorted(set(record_ids))
        if not selected:
            return 0
        connection = sqlite3.connect(self.db_path)
        try:
            removed = 0
            # Keep parameter counts portable across supported SQLite builds.
            for start in range(0, len(selected), 500):
                batch = selected[start : start + 500]
                placeholders = ",".join("?" for _ in batch)
                removed += connection.execute(
                    f"DELETE FROM scan_history WHERE id IN ({placeholders})", batch
                ).rowcount
            connection.commit()
            return removed
        finally:
            connection.close()
