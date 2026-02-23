import csv
import io
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


SYSLOG_RE = re.compile(
    r"^(?:<(?P<priority>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>[\w\-.]+)\s+(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

NGINX_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>[^\s]+)\s+HTTP/[^"]+"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"(?:\s+(?P<rt>[\d.]+))?$'
)

LEVEL_HINTS = {
    "error": "ERROR",
    "err": "ERROR",
    "warn": "WARN",
    "warning": "WARN",
    "info": "INFO",
    "debug": "DEBUG",
    "trace": "DEBUG",
    "critical": "ERROR",
    "fatal": "ERROR",
}

ISO_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
NUM_RE = re.compile(r"[-+]?\d*\.\d+|[-+]?\d+")


def _normalize_timestamp(value: Optional[str]) -> str:
    if not value:
        return datetime.utcnow().isoformat()
    val = value.strip()
    if not val:
        return datetime.utcnow().isoformat()
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S.%f",
        "%b %d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S%z",
    ]
    for f in formats:
        try:
            dt = datetime.strptime(val, f)
            if dt.year == 1900:
                dt = dt.replace(year=datetime.utcnow().year)
            return dt.isoformat()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(val.replace("Z", "+00:00")).isoformat()
    except Exception:
        return datetime.utcnow().isoformat()


def _guess_level(*values: str) -> str:
    for value in values:
        if not value:
            continue
        low = str(value).lower()
        for k, v in LEVEL_HINTS.items():
            if re.search(rf"\b{k}\b", low):
                return v
    return "INFO"


def _extract_numbers(text: str) -> Dict[str, float]:
    metrics: Dict[str, float] = {}
    for i, n in enumerate(NUM_RE.findall(text or "")):
        try:
            metrics[f"value_{i+1}"] = float(n)
        except ValueError:
            continue
    return metrics


def _parse_json_obj(obj: Dict[str, Any], fallback_source: str, raw: str) -> Dict[str, Any]:
    ts = obj.get("timestamp") or obj.get("time") or obj.get("ts")
    level = obj.get("level") or obj.get("severity") or obj.get("log_level") or ""
    msg = obj.get("message") or obj.get("msg") or obj.get("event") or raw
    source = obj.get("source") or obj.get("service") or obj.get("app") or fallback_source

    numeric_fields = {}
    string_fields = {}
    for k, v in obj.items():
        if isinstance(v, bool) or v is None:
            continue
        if isinstance(v, (int, float)):
            numeric_fields[k] = float(v)
        elif isinstance(v, str):
            string_fields[k] = v
            try:
                numeric_fields[k] = float(v)
            except ValueError:
                pass

    return {
        "timestamp": _normalize_timestamp(str(ts) if ts is not None else None),
        "source": str(source),
        "level": _guess_level(str(level), str(msg)),
        "message": str(msg),
        "raw_line": raw,
        "format_detected": "json",
        "numeric_fields": numeric_fields,
        "string_fields": string_fields,
    }


def detect_and_parse(text: str, source: str = "ingest") -> List[Dict[str, Any]]:
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        return []

    # whole-body JSON array or object
    try:
        body_json = json.loads(text)
        if isinstance(body_json, dict):
            return [_parse_json_obj(body_json, source, text.strip())]
        if isinstance(body_json, list):
            parsed = []
            for item in body_json:
                if isinstance(item, dict):
                    parsed.append(_parse_json_obj(item, source, json.dumps(item)))
                else:
                    raw = str(item)
                    parsed.extend(detect_and_parse(raw, source=source))
            return parsed
    except json.JSONDecodeError:
        pass

    # Try line-by-line JSON lines
    jsonl_ok = True
    jsonl_entries: List[Dict[str, Any]] = []
    for line in lines:
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                jsonl_entries.append(_parse_json_obj(obj, source, line))
            else:
                jsonl_ok = False
                break
        except json.JSONDecodeError:
            jsonl_ok = False
            break
    if jsonl_ok and jsonl_entries:
        return jsonl_entries

    # CSV/TSV detection
    if len(lines) >= 2:
        sample = "\n".join(lines[:10])
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",\t|;")
            reader = csv.DictReader(io.StringIO(text), dialect=dialect)
            if reader.fieldnames and len(reader.fieldnames) > 1:
                out = []
                for row in reader:
                    if not row:
                        continue
                    row_clean = {k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items() if k}
                    msg = row_clean.get("message") or row_clean.get("msg") or " ".join(
                        [f"{k}={v}" for k, v in row_clean.items() if v]
                    )
                    ts = row_clean.get("timestamp") or row_clean.get("time") or row_clean.get("date")
                    level = row_clean.get("level") or row_clean.get("severity") or ""
                    src = row_clean.get("source") or row_clean.get("service") or source
                    numeric_fields = {}
                    string_fields = {}
                    for k, v in row_clean.items():
                        if v in (None, ""):
                            continue
                        try:
                            numeric_fields[k] = float(v)
                        except Exception:
                            string_fields[k] = str(v)
                    out.append(
                        {
                            "timestamp": _normalize_timestamp(str(ts) if ts else None),
                            "source": str(src),
                            "level": _guess_level(str(level), str(msg)),
                            "message": str(msg),
                            "raw_line": ",".join([str(x) for x in row_clean.values()]),
                            "format_detected": "csv",
                            "numeric_fields": numeric_fields,
                            "string_fields": string_fields,
                        }
                    )
                if out:
                    return out
        except Exception:
            pass

    parsed = []
    for line in lines:
        m = SYSLOG_RE.match(line)
        if m:
            gd = m.groupdict()
            msg = gd.get("msg", "")
            parsed.append(
                {
                    "timestamp": _normalize_timestamp(gd.get("ts")),
                    "source": gd.get("proc") or source,
                    "level": _guess_level(msg),
                    "message": msg,
                    "raw_line": line,
                    "format_detected": "syslog",
                    "numeric_fields": _extract_numbers(msg),
                    "string_fields": {"hostname": gd.get("host", "")},
                }
            )
            continue

        n = NGINX_RE.match(line)
        if n:
            gd = n.groupdict()
            status = int(gd["status"])
            numeric_fields = {
                "status": float(status),
                "bytes": float(gd["size"]) if gd.get("size") and gd["size"].isdigit() else 0.0,
            }
            if gd.get("rt"):
                try:
                    numeric_fields["response_time"] = float(gd["rt"])
                except ValueError:
                    pass
            parsed.append(
                {
                    "timestamp": _normalize_timestamp(gd.get("ts")),
                    "source": source if source != "ingest" else "nginx",
                    "level": "ERROR" if status >= 500 else ("WARN" if status >= 400 else "INFO"),
                    "message": f"{gd.get('method')} {gd.get('path')} -> {status}",
                    "raw_line": line,
                    "format_detected": "access_log",
                    "numeric_fields": numeric_fields,
                    "string_fields": {
                        "ip": gd.get("ip", ""),
                        "method": gd.get("method", ""),
                        "path": gd.get("path", ""),
                        "status_group": f"{status // 100}xx",
                    },
                }
            )
            continue

        # fallback
        ts_match = ISO_TS_RE.search(line)
        ts = ts_match.group(0) if ts_match else None
        parsed.append(
            {
                "timestamp": _normalize_timestamp(ts),
                "source": source,
                "level": _guess_level(line),
                "message": line[:1000],
                "raw_line": line,
                "format_detected": "plain",
                "numeric_fields": _extract_numbers(line),
                "string_fields": {},
            }
        )
    return parsed
