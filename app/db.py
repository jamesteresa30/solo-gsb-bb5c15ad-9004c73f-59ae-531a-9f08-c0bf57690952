"""SQLite 持久化层（标准库 sqlite3）。"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    project_version TEXT DEFAULT '',
    project_license TEXT NOT NULL,
    policy_key TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exceptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    package_id TEXT NOT NULL,
    note TEXT DEFAULT '',
    rule TEXT DEFAULT '',
    distribution TEXT DEFAULT '',
    approved_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exceptions_project ON exceptions(project_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_exceptions_key
    ON exceptions(project_id, package_id, rule);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        if self.path == ":memory:":
            # 测试模式：复用同一内存连接，避免每个连接拿到独立空库
            assert self._mem_conn is not None
            try:
                yield self._mem_conn
                self._mem_conn.commit()
            except Exception:
                self._mem_conn.rollback()
                raise
            return
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init(self) -> None:
        if self.path == ":memory:":
            self._mem_conn = sqlite3.connect(
                ":memory:", check_same_thread=False
            )
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA foreign_keys = ON")
        with self.connect() as conn:
            self._migrate(conn)
            conn.executescript(SCHEMA)
            if self.path != ":memory:":
                conn.execute("PRAGMA journal_mode=WAL")

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """把早期版本的 exceptions 表升级到带 rule/distribution 的新结构。"""
        cols = {
            r[1] for r in conn.execute("PRAGMA table_info(exceptions)").fetchall()
        }
        if not cols:
            return  # 全新库，SCHEMA 会直接创建新表
        if "rule" in cols:
            return
        conn.executescript(
            """
            ALTER TABLE exceptions RENAME TO exceptions_legacy;
            CREATE TABLE exceptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                package_id TEXT NOT NULL,
                note TEXT DEFAULT '',
                rule TEXT DEFAULT '',
                distribution TEXT DEFAULT '',
                approved_at TEXT NOT NULL
            );
            INSERT INTO exceptions(id, project_id, package_id, note, rule, distribution, approved_at)
            SELECT id, project_id, package_id, note, '', '', approved_at FROM exceptions_legacy;
            DROP TABLE exceptions_legacy;
            """
        )

    # ------------------------------------------------------------------ #

    def create_project(self, name: str, project_version: str, project_license: str,
                       policy_key: str, manifest: dict) -> int:
        ts = now_iso()
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO projects(name, project_version, project_license, policy_key, "
                "manifest_json, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                (name, project_version, project_license, policy_key,
                 json.dumps(manifest, ensure_ascii=False), ts, ts),
            )
            return int(cur.lastrowid)

    def list_projects(self, limit: int = 50) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, name, project_version, project_license, policy_key, "
                "created_at, updated_at FROM projects ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_project(self, project_id: int) -> Optional[dict]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["manifest"] = json.loads(data.pop("manifest_json"))
        return data

    def delete_project(self, project_id: int) -> bool:
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            return cur.rowcount > 0

    def touch_project(self, project_id: int) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE projects SET updated_at = ? WHERE id = ?",
                (now_iso(), project_id),
            )

    # ------------------------------------------------------------------ #

    def list_exceptions(self, project_id: int) -> list[dict]:
        """返回项目下全部例外记录（多制品模式下同一包可能有多条规则例外）。"""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT package_id, note, rule, distribution, approved_at FROM exceptions "
                "WHERE project_id = ? ORDER BY approved_at",
                (project_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def add_exception(self, project_id: int, package_id: str, note: str,
                      rule: str = "", distribution: str = "") -> dict:
        """新增/更新一条例外。

        多制品模式以 ``(project_id, package_id, rule)`` 为唯一键；
        单制品模式 rule 为空串，与旧版按 package_id 唯一的行为一致。
        """
        ts = now_iso()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO exceptions(project_id, package_id, note, rule, distribution, approved_at) "
                "VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(project_id, package_id, rule) "
                "DO UPDATE SET note=excluded.note, distribution=excluded.distribution, "
                "approved_at=excluded.approved_at",
                (project_id, package_id, note, rule, distribution, ts),
            )
            conn.execute(
                "UPDATE projects SET updated_at = ? WHERE id = ?", (ts, project_id)
            )
        return {
            "package_id": package_id,
            "note": note,
            "rule": rule,
            "distribution": distribution,
            "approved_at": ts,
        }

    def remove_exception(self, project_id: int, package_id: str,
                         rule: Optional[str] = None) -> bool:
        """撤销例外。

        提供 ``rule`` 时精确删除该 (package_id, rule) 记录（多制品模式）；
        否则删除该包的全部例外（单制品模式）。
        """
        with self.connect() as conn:
            if rule is None:
                cur = conn.execute(
                    "DELETE FROM exceptions WHERE project_id = ? AND package_id = ?",
                    (project_id, package_id),
                )
            else:
                cur = conn.execute(
                    "DELETE FROM exceptions WHERE project_id = ? AND package_id = ? AND rule = ?",
                    (project_id, package_id, rule),
                )
            if cur.rowcount:
                conn.execute(
                    "UPDATE projects SET updated_at = ? WHERE id = ?",
                    (now_iso(), project_id),
                )
            return cur.rowcount > 0
