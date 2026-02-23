import json
import logging
import os
import sqlite3
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import alerts
from detector import detect_and_parse
from extractor import derive_metrics_and_categories

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s :: %(message)s")
logger = logging.getLogger("loglens")

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
DB_PATH = BASE_DIR / "loglens.db"

app = FastAPI(title="LogLens", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

conn: Optional[sqlite3.Connection] = None
DB_LOCK = threading.Lock()


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS log_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    raw_line TEXT NOT NULL,
    format_detected TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_entry_id INTEGER NOT NULL,
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(log_entry_id) REFERENCES log_entries(id)
);

CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_entry_id INTEGER NOT NULL,
    category_name TEXT NOT NULL,
    category_value TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(log_entry_id) REFERENCES log_entries(id)
);

CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_name TEXT NOT NULL,
    condition TEXT NOT NULL,
    threshold REAL NOT NULL,
    window_seconds INTEGER NOT NULL,
    webhook_url TEXT,
    email TEXT,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    triggered_at TEXT NOT NULL,
    metric_value REAL NOT NULL,
    notified INTEGER NOT NULL,
    FOREIGN KEY(rule_id) REFERENCES alert_rules(id)
);

CREATE INDEX IF NOT EXISTS idx_log_entries_source_ts ON log_entries(source, timestamp);
CREATE INDEX IF NOT EXISTS idx_metrics_name_ts ON metrics(metric_name, timestamp);
CREATE INDEX IF NOT EXISTS idx_categories_name ON categories(category_name, category_value);
"""


def init_db() -> sqlite3.Connection:
    database = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    database.execute("PRAGMA journal_mode=WAL;")
    database.executescript(SCHEMA_SQL)
    database.commit()
    return database


@app.on_event("startup")
async def startup() -> None:
    global conn
    conn = init_db()
    logger.info("Database initialized at %s", DB_PATH)
    app.state.alert_task = app.state.loop_task = None

    import asyncio

    async def _alert_loop() -> None:
        while True:
            try:
                with DB_LOCK:
                    trig = alerts.check_rules(conn)
                if trig:
                    logger.warning("Triggered %d alerts", len(trig))
            except Exception as exc:
                logger.exception("Alert loop error: %s", exc)
            await asyncio.sleep(30)

    app.state.loop_task = asyncio.create_task(_alert_loop())


@app.on_event("shutdown")
async def shutdown() -> None:
    task = getattr(app.state, "loop_task", None)
    if task:
        task.cancel()
    if conn:
        conn.close()


@app.get("/")
def root() -> FileResponse:
    return FileResponse(str(STATIC_DIR / "index.html"))


def _insert_entries(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not conn:
        raise HTTPException(status_code=500, detail="Database unavailable")

    ingested = 0
    by_format = defaultdict(int)
    with DB_LOCK:
        cur = conn.cursor()
        for e in entries:
            ts = e.get("timestamp") or datetime.utcnow().isoformat()
            cur.execute(
                """
                INSERT INTO log_entries (timestamp, source, level, message, raw_line, format_detected, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    e.get("source", "ingest"),
                    e.get("level", "INFO"),
                    e.get("message", ""),
                    e.get("raw_line", ""),
                    e.get("format_detected", "plain"),
                    datetime.utcnow().isoformat(),
                ),
            )
            log_entry_id = cur.lastrowid
            by_format[e.get("format_detected", "plain")] += 1

            for metric_name, metric_value in (e.get("numeric_fields") or {}).items():
                cur.execute(
                    "INSERT INTO metrics (log_entry_id, metric_name, metric_value, timestamp) VALUES (?, ?, ?, ?)",
                    (log_entry_id, metric_name, float(metric_value), ts),
                )

            for cat_name, cat_val in (e.get("string_fields") or {}).items():
                if cat_val is None:
                    continue
                cur.execute(
                    "INSERT INTO categories (log_entry_id, category_name, category_value, timestamp) VALUES (?, ?, ?, ?)",
                    (log_entry_id, str(cat_name), str(cat_val), ts),
                )
            ingested += 1
        conn.commit()
    return {"ingested": ingested, "formats": dict(by_format)}


@app.post("/api/ingest")
async def ingest(request: Request, source: str = Query(default="ingest")) -> JSONResponse:
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="Empty request body")
    content_type = request.headers.get("content-type", "")

    text = body.decode("utf-8", errors="replace")
    parsed: List[Dict[str, Any]] = []

    try:
        if "application/json" in content_type:
            obj = json.loads(text)
            if isinstance(obj, list):
                text_for_detector = json.dumps(obj)
            elif isinstance(obj, dict):
                text_for_detector = json.dumps(obj)
            else:
                text_for_detector = text
            parsed = detect_and_parse(text_for_detector, source=source)
        else:
            parsed = detect_and_parse(text, source=source)
    except json.JSONDecodeError:
        parsed = detect_and_parse(text, source=source)

    if not parsed:
        raise HTTPException(status_code=400, detail="No log entries parsed")

    for p in parsed:
        if source and source != "ingest":
            p["source"] = source

    result = _insert_entries(parsed)
    return JSONResponse({"status": "ok", **result})


@app.get("/api/sources")
def get_sources() -> Dict[str, Any]:
    with DB_LOCK:
        cur = conn.execute("SELECT DISTINCT source FROM log_entries ORDER BY source")
        rows = [r[0] for r in cur.fetchall()]
    return {"sources": rows}


@app.get("/api/metrics")
def get_metrics(source: Optional[str] = None, from_: Optional[str] = Query(default=None, alias="from"), to: Optional[str] = None):
    filters = ["1=1"]
    params: List[Any] = []
    if source:
        filters.append("le.source = ?")
        params.append(source)
    if from_:
        filters.append("m.timestamp >= ?")
        params.append(from_)
    if to:
        filters.append("m.timestamp <= ?")
        params.append(to)

    sql = f"""
    SELECT m.metric_name, m.timestamp, m.metric_value
    FROM metrics m
    JOIN log_entries le ON le.id = m.log_entry_id
    WHERE {' AND '.join(filters)}
    ORDER BY m.timestamp ASC
    """
    with DB_LOCK:
        cur = conn.execute(sql, params)
        rows = cur.fetchall()

    series: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for name, ts, value in rows:
        series[name].append({"t": ts, "v": value})
    return {"metrics": series}


@app.get("/api/categories")
def get_categories(source: Optional[str] = None):
    filters = ["1=1"]
    params: List[Any] = []
    if source:
        filters.append("le.source = ?")
        params.append(source)
    sql = f"""
    SELECT c.category_name, c.category_value, COUNT(*)
    FROM categories c
    JOIN log_entries le ON le.id = c.log_entry_id
    WHERE {' AND '.join(filters)}
    GROUP BY c.category_name, c.category_value
    ORDER BY c.category_name ASC, COUNT(*) DESC
    """
    with DB_LOCK:
        rows = conn.execute(sql, params).fetchall()

    result: Dict[str, Dict[str, int]] = defaultdict(dict)
    for cname, cval, count in rows:
        result[cname][cval] = count
    return {"categories": result}


@app.get("/api/logs")
def get_logs(source: Optional[str] = None, level: Optional[str] = None, limit: int = 100):
    limit = min(max(limit, 1), 1000)
    filters = ["1=1"]
    params: List[Any] = []
    if source:
        filters.append("source = ?")
        params.append(source)
    if level:
        filters.append("level = ?")
        params.append(level)
    sql = f"""
    SELECT id, timestamp, source, level, message, raw_line, format_detected, created_at
    FROM log_entries
    WHERE {' AND '.join(filters)}
    ORDER BY timestamp DESC
    LIMIT ?
    """
    params.append(limit)
    with DB_LOCK:
        rows = conn.execute(sql, params).fetchall()
    out = [
        {
            "id": r[0],
            "timestamp": r[1],
            "source": r[2],
            "level": r[3],
            "message": r[4],
            "raw_line": r[5],
            "format": r[6],
            "created_at": r[7],
        }
        for r in rows
    ]
    return {"logs": out}


@app.get("/api/alerts")
def get_alerts():
    with DB_LOCK:
        rules = conn.execute(
            "SELECT id, metric_name, condition, threshold, window_seconds, webhook_url, email, enabled FROM alert_rules"
        ).fetchall()
        history = conn.execute(
            "SELECT id, rule_id, triggered_at, metric_value, notified FROM alert_history ORDER BY triggered_at DESC LIMIT 100"
        ).fetchall()
    return {
        "rules": [
            {
                "id": r[0],
                "metric_name": r[1],
                "condition": r[2],
                "threshold": r[3],
                "window_seconds": r[4],
                "webhook_url": r[5],
                "email": r[6],
                "enabled": bool(r[7]),
            }
            for r in rules
        ],
        "history": [
            {"id": h[0], "rule_id": h[1], "triggered_at": h[2], "metric_value": h[3], "notified": bool(h[4])}
            for h in history
        ],
    }


@app.post("/api/alerts/rules")
async def create_alert_rule(request: Request):
    data = await request.json()
    required = ["metric_name", "condition", "threshold", "window_seconds"]
    for key in required:
        if key not in data:
            raise HTTPException(status_code=400, detail=f"Missing required field: {key}")

    if data["condition"] not in {"gt", "lt", "eq"}:
        raise HTTPException(status_code=400, detail="condition must be gt/lt/eq")

    with DB_LOCK:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO alert_rules (metric_name, condition, threshold, window_seconds, webhook_url, email, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["metric_name"],
                data["condition"],
                float(data["threshold"]),
                int(data["window_seconds"]),
                data.get("webhook_url"),
                data.get("email"),
                1,
            ),
        )
        conn.commit()
        rid = cur.lastrowid
    return {"status": "created", "id": rid}


@app.delete("/api/alerts/rules/{rule_id}")
def delete_alert_rule(rule_id: int):
    with DB_LOCK:
        cur = conn.cursor()
        cur.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "deleted", "id": rule_id}


@app.get("/api/stats")
def stats():
    now = datetime.utcnow()
    minute_ago = (now - timedelta(minutes=1)).isoformat()
    with DB_LOCK:
        total = conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
        per_min = conn.execute("SELECT COUNT(*) FROM log_entries WHERE timestamp >= ?", (minute_ago,)).fetchone()[0]
        errors = conn.execute(
            "SELECT COUNT(*) FROM log_entries WHERE level = 'ERROR'"
        ).fetchone()[0]
        top_sources = conn.execute(
            "SELECT source, COUNT(*) AS c FROM log_entries GROUP BY source ORDER BY c DESC LIMIT 10"
        ).fetchall()
        active_alerts = conn.execute("SELECT COUNT(*) FROM alert_rules WHERE enabled = 1").fetchone()[0]

    return {
        "total_entries": total,
        "entries_per_min": per_min,
        "error_rate": (errors / total) if total else 0.0,
        "top_sources": [{"source": s, "count": c} for s, c in top_sources],
        "active_alerts": active_alerts,
    }


def print_banner() -> None:
    banner = r"""
 _                _                    
| |    ___   __ _| |    ___ _ __  ___ 
| |   / _ \ / _` | |   / _ \ '_ \/ __|
| |__| (_) | (_| | |__|  __/ | | \__ \
|_____\___/ \__, |_____\___|_| |_|___/
            |___/                     
"""
    print(banner)
    print("LogLens running at http://localhost:8000")


if __name__ == "__main__":
    print_banner()
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
