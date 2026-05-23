from __future__ import annotations

"""Browser Forensics Cell — analyze Chrome/Firefox history, cookies, downloads, bookmarks.

All tools use Python stdlib (sqlite3, json) — zero external dependencies.
"""

import datetime
import json
import sqlite3
from datetime import timezone
from pathlib import Path
from typing import Any

from forhacker.plugin.base import BasePlugin, Tool


class BrowserForensicsPlugin(BasePlugin):
    name = "browser-forensics"
    version = "0.1.0"
    domain = "forensics"
    risk_levels = {
        "chrome_history": "LOW",
        "firefox_history": "LOW",
        "chrome_cookies": "LOW",
        "browser_downloads": "LOW",
        "extract_bookmarks": "LOW",
    }

    def register_tools(self) -> list[Tool]:
        return [
            Tool(
                name="chrome_history",
                description="Parse Chrome/Chromium History SQLite database",
                domain="forensics",
                risk_level="LOW",
            ),
            Tool(
                name="firefox_history",
                description="Parse Firefox places.sqlite browsing history",
                domain="forensics",
                risk_level="LOW",
            ),
            Tool(
                name="chrome_cookies",
                description="Parse Chrome/Chromium Cookies SQLite database",
                domain="forensics",
                risk_level="LOW",
            ),
            Tool(
                name="browser_downloads",
                description="Parse browser download history from Chrome/Firefox",
                domain="forensics",
                risk_level="LOW",
            ),
            Tool(
                name="extract_bookmarks",
                description="Extract bookmarks from Chrome/Firefox JSON exports",
                domain="forensics",
                risk_level="LOW",
            ),
        ]


def _chrome_time(micros: int) -> str:
    """Convert Chrome microsecond timestamp (since 1601-01-01) to ISO 8601."""
    if micros <= 0:
        return ""
    try:
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=micros)
        return dt.isoformat() + "Z"
    except (ValueError, OverflowError):
        return str(micros)


def _query_sqlite(path: Path, query: str, params: tuple = ()) -> list[dict[str, Any]]:
    """Execute a query on a SQLite DB and return rows as dicts."""
    conn = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def run_chrome_history(target: str, max_rows: int = 200) -> dict[str, Any]:
    """Parse Chrome/Chromium History SQLite database."""
    path = Path(target)
    if not path.exists():
        return {"error": f"File not found: {target}"}

    try:
        rows = _query_sqlite(
            path,
            "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?",
            (max_rows,),
        )
    except sqlite3.Error as e:
        return {"error": f"Failed to read Chrome history: {e}"}

    entries = []
    for r in rows:
        entries.append(
            {
                "url": r.get("url", ""),
                "title": r.get("title", ""),
                "visit_count": r.get("visit_count", 0),
                "last_visit": _chrome_time(r.get("last_visit_time", 0) or 0),
            }
        )

    return {
        "file": str(path.absolute()),
        "entry_count": len(entries),
        "entries": entries,
    }


def run_firefox_history(target: str, max_rows: int = 200) -> dict[str, Any]:
    """Parse Firefox places.sqlite browsing history."""
    path = Path(target)
    if not path.exists():
        return {"error": f"File not found: {target}"}

    try:
        rows = _query_sqlite(
            path,
            "SELECT p.url, p.title, p.visit_count, p.last_visit_date / 1000 AS last_visit_unix "
            "FROM moz_places p ORDER BY p.last_visit_date DESC LIMIT ?",
            (max_rows,),
        )
    except sqlite3.Error as e:
        return {"error": f"Failed to read Firefox history: {e}"}

    entries = []
    for r in rows:
        ts = ""
        if r.get("last_visit_unix"):
            try:
                ts = datetime.datetime.fromtimestamp(r["last_visit_unix"], tz=timezone.utc).isoformat()
            except (ValueError, OSError):
                ts = str(r["last_visit_unix"])
        entries.append(
            {
                "url": r.get("url", ""),
                "title": r.get("title", ""),
                "visit_count": r.get("visit_count", 0),
                "last_visit": ts,
            }
        )

    return {
        "file": str(path.absolute()),
        "entry_count": len(entries),
        "entries": entries,
    }


def run_chrome_cookies(target: str, max_rows: int = 200) -> dict[str, Any]:
    """Parse Chrome/Chromium Cookies SQLite database."""
    path = Path(target)
    if not path.exists():
        return {"error": f"File not found: {target}"}

    try:
        rows = _query_sqlite(
            path,
            "SELECT host_key, name, encrypted_value, expires_utc, is_secure, is_httponly "
            "FROM cookies ORDER BY creation_utc DESC LIMIT ?",
            (max_rows,),
        )
    except sqlite3.Error as e:
        return {"error": f"Failed to read Chrome cookies: {e}"}

    entries = []
    for r in rows:
        entries.append(
            {
                "host": r.get("host_key", ""),
                "name": r.get("name", ""),
                "encrypted": bool(r.get("encrypted_value")),
                "expires": _chrome_time(r.get("expires_utc", 0) or 0),
                "secure": bool(r.get("is_secure")),
                "httponly": bool(r.get("is_httponly")),
            }
        )

    return {
        "file": str(path.absolute()),
        "cookie_count": len(entries),
        "cookies": entries,
    }


def run_browser_downloads(target: str, max_rows: int = 200) -> dict[str, Any]:
    """Parse browser download history (Chrome/Chromium format)."""
    path = Path(target)
    if not path.exists():
        return {"error": f"File not found: {target}"}

    try:
        rows = _query_sqlite(
            path,
            "SELECT target_path, tab_url, total_bytes, received_bytes, "
            "start_time, end_time, state, danger_type "
            "FROM downloads ORDER BY start_time DESC LIMIT ?",
            (max_rows,),
        )
    except sqlite3.Error as e:
        return {"error": f"Failed to read download history: {e}"}

    state_map = {1: "complete", 2: "interrupted", 3: "in_progress", 4: "cancelled"}
    entries = []
    for r in rows:
        state = r.get("state", -1)
        entries.append(
            {
                "path": r.get("target_path", ""),
                "source_url": r.get("tab_url", ""),
                "total_bytes": r.get("total_bytes", 0),
                "received_bytes": r.get("received_bytes", 0),
                "start_time": _chrome_time(r.get("start_time", 0) or 0),
                "end_time": _chrome_time(r.get("end_time", 0) or 0),
                "state": state_map.get(state, f"unknown({state})"),
                "dangerous": r.get("danger_type", 0) > 0,
            }
        )

    return {
        "file": str(path.absolute()),
        "download_count": len(entries),
        "downloads": entries,
    }


def run_extract_bookmarks(target: str, max_rows: int = 200) -> dict[str, Any]:
    """Extract bookmarks from Chrome/Firefox Bookmarks JSON file."""
    path = Path(target)
    if not path.exists():
        return {"error": f"File not found: {target}"}

    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}"}

    bookmarks: list[dict[str, str]] = []

    def _walk(node: dict, depth: int = 0):
        if len(bookmarks) >= max_rows:
            return
        node_type = node.get("type", "")
        if node_type == "url" and node.get("url"):
            bookmarks.append(
                {
                    "name": node.get("name", ""),
                    "url": node.get("url", ""),
                    "date_added": _chrome_time(int(node.get("date_added", 0))),
                }
            )
        elif node_type == "folder":
            for child in node.get("children", []):
                _walk(child, depth + 1)

    roots = data.get("roots", {})
    for root_name, root_node in roots.items():
        if isinstance(root_node, dict):
            _walk(root_node)

    return {
        "file": str(path.absolute()),
        "bookmark_count": len(bookmarks),
        "bookmarks": bookmarks[:max_rows],
    }
