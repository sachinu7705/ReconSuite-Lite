
import sqlite3
import json
import time
from pathlib import Path

try:
    from .storage import get_database_path
except ImportError:
    from storage import get_database_path

DB_PATH = get_database_path("port_history.db")


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_history():
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS port_scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                results TEXT NOT NULL,
                created_at REAL,
                finished_at REAL
            )
        """)


def save_scan(job):
    with connect() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO port_scans
            (id, target, status, results, created_at, finished_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            job["id"],
            job["target"],
            job["status"],
            json.dumps(job.get("results", [])),
            job.get("created_at", time.time()),
            job.get("finished_at"),
        ))


def get_scan(scan_id):
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM port_scans WHERE id = ?",
            (scan_id,)
        ).fetchone()

    if not row:
        return None

    result = dict(row)
    result["results"] = json.loads(result["results"])
    return result


def list_scans():
    with connect() as conn:
        rows = conn.execute("""
            SELECT id, target, status, created_at,
                   finished_at, results
            FROM port_scans
            ORDER BY created_at DESC
        """).fetchall()

    return [
        {
            "id": row["id"],
            "target": row["target"],
            "status": row["status"],
            "created_at": row["created_at"],
            "finished_at": row["finished_at"],
            "open_ports": len(json.loads(row["results"]))
        }
        for row in rows
    ]

def delete_scan(scan_id):
    with connect() as conn:
        cursor = conn.execute(
            "DELETE FROM port_scans WHERE id = ?",
            (scan_id,)
        )
        return cursor.rowcount > 0