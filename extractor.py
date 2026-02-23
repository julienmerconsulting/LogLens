from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Tuple


def metric_name_normalize(name: str) -> str:
    return (
        (name or "metric")
        .strip()
        .lower()
        .replace(" ", "_")
        .replace("-", "_")
    )


def derive_metrics_and_categories(entries: List[Dict]) -> Tuple[Dict[str, List[float]], Dict[str, Counter]]:
    numeric_map: Dict[str, List[float]] = defaultdict(list)
    category_map: Dict[str, Counter] = defaultdict(Counter)

    for e in entries:
        for key, val in (e.get("numeric_fields") or {}).items():
            mname = metric_name_normalize(key)
            try:
                numeric_map[mname].append(float(val))
                if mname == "status":
                    code = int(float(val))
                    category_map["status_group"][f"{code // 100}xx"] += 1
            except Exception:
                continue

        for key, val in (e.get("string_fields") or {}).items():
            if val is None:
                continue
            category_map[metric_name_normalize(key)][str(val)] += 1

        msg = (e.get("message") or "").lower()
        if "ms" in msg or "latency" in msg or "duration" in msg or "response_time" in msg:
            pass

    varying_numeric = {k: v for k, v in numeric_map.items() if len(set(v)) > 1 or len(v) == 1}
    compact_categories = {
        k: c for k, c in category_map.items() if 0 < len(c) <= 50
    }
    return varying_numeric, compact_categories


def summarize_source(entries_per_min: float, total: int, error_count: int) -> Dict:
    return {
        "entries_per_min": round(entries_per_min, 3),
        "total": total,
        "error_rate": (error_count / total) if total else 0.0,
    }
