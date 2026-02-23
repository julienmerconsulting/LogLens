import json
import logging
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
from typing import Any, Dict, List, Optional
from urllib import request

logger = logging.getLogger("loglens.alerts")


def evaluate_condition(value: float, condition: str, threshold: float) -> bool:
    if condition == "gt":
        return value > threshold
    if condition == "lt":
        return value < threshold
    if condition == "eq":
        return value == threshold
    return False


def send_webhook(url: str, payload: Dict[str, Any]) -> bool:
    if not url:
        return False
    try:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with request.urlopen(req, timeout=8) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        logger.warning("Webhook send failed: %s", exc)
        return False


def send_email(recipient: str, payload: Dict[str, Any], smtp_host: str = "localhost", smtp_port: int = 25) -> bool:
    if not recipient:
        return False
    msg = EmailMessage()
    msg["Subject"] = f"LogLens Alert Triggered: {payload.get('metric_name')}"
    msg["From"] = "loglens@localhost"
    msg["To"] = recipient
    msg.set_content(json.dumps(payload, indent=2))
    try:
        with smtplib.SMTP(host=smtp_host, port=smtp_port, timeout=8) as client:
            client.send_message(msg)
            return True
    except Exception as exc:
        logger.warning("Email send failed: %s", exc)
        return False


def check_rules(conn) -> List[Dict[str, Any]]:
    cur = conn.cursor()
    cur.execute(
        "SELECT id, metric_name, condition, threshold, window_seconds, webhook_url, email, enabled FROM alert_rules WHERE enabled = 1"
    )
    rules = cur.fetchall()
    triggered: List[Dict[str, Any]] = []

    for rule in rules:
        rid, metric_name, condition, threshold, window_seconds, webhook_url, email, enabled = rule
        since = (datetime.utcnow() - timedelta(seconds=max(int(window_seconds or 60), 5))).isoformat()
        cur.execute(
            """
            SELECT AVG(metric_value) FROM metrics
            WHERE metric_name = ? AND timestamp >= ?
            """,
            (metric_name, since),
        )
        row = cur.fetchone()
        metric_value = row[0] if row and row[0] is not None else None
        if metric_value is None:
            continue

        if evaluate_condition(float(metric_value), condition, float(threshold)):
            payload = {
                "rule_id": rid,
                "metric_name": metric_name,
                "condition": condition,
                "threshold": threshold,
                "window_seconds": window_seconds,
                "metric_value": metric_value,
                "triggered_at": datetime.utcnow().isoformat(),
            }
            notified = False
            if webhook_url:
                notified = send_webhook(webhook_url, payload) or notified
            if email:
                notified = send_email(email, payload) or notified

            cur.execute(
                "INSERT INTO alert_history (rule_id, triggered_at, metric_value, notified) VALUES (?, ?, ?, ?)",
                (rid, payload["triggered_at"], float(metric_value), 1 if notified else 0),
            )
            triggered.append(payload)

    conn.commit()
    return triggered
