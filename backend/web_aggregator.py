"""网页日志降噪 + 聚合（与数据源无关；深信服 / IP-Guard 网页日志通用）。

降噪：过滤证书校验(OCSP/CRL/lencr)、CDN、静态资源、广告跟踪等噪声域名——
      这类在上网日志里往往占 50-70%，对行为分析无价值。
聚合：按 用户 × 域名 × 时间桶(默认10分钟) 合并计数，把"一人浏览几百次请求"
      压成"几条有意义的域名访问"，大幅降低入库行数与 AI 调用。
"""
from __future__ import annotations

from collections import defaultdict

from models import CanonicalEvent

# 噪声域名特征（子串匹配，小写）
NOISE_HINTS = [
    "lencr.org", "ocsp.", "crl.", "ct.comodo", "akamaiedge", "akamai", "edgesuite",
    "doubleclick", "googlesyndication", "googletagmanager", "google-analytics", "google.",
    "hm.baidu.com", "hmma.baidu.com", "px.ads", "adservice", "scorecardresearch",
    "cnzz", "umeng", "push", "telemetry", "sns-stat",
]
# 噪声资源扩展名（URL 路径后缀）
NOISE_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2",
             ".svg", ".ttf", ".otf", ".map", ".webp")


def is_noise(domain: str, url: str) -> bool:
    d = (domain or "").lower()
    if any(h in d for h in NOISE_HINTS):
        return True
    u = (url or "").lower()
    path = u.split("/", 3)[-1] if u.count("/") >= 3 else ""
    path = path.split("?", 1)[0]
    if path and any(path.endswith(e) for e in NOISE_EXT):
        return True
    return False


def aggregate(events, bucket_minutes: int = 10) -> list:
    """对 WEB 事件降噪 + 聚合。返回聚合后的 CanonicalEvent 列表
    （每 用户×域名×时间桶 一条，count=访问次数）。非 WEB 事件原样保留。"""
    buckets = {}
    passthrough = []
    for e in events:
        if e.category != "WEB":
            passthrough.append(e)
            continue
        domain = (e.raw or {}).get("domain") or ""
        if is_noise(domain, e.target_value):
            continue  # 降噪
        b = e.occurred_at.replace(minute=(e.occurred_at.minute // bucket_minutes) * bucket_minutes,
                                  second=0, microsecond=0)
        key = (e.employee_id, domain, b)
        if key not in buckets:
            buckets[key] = {"count": 0, "first": e.occurred_at, "last": e.occurred_at,
                            "category": (e.raw or {}).get("category"), "sample": e}
        rec = buckets[key]
        rec["count"] += 1
        if e.occurred_at < rec["first"]:
            rec["first"] = e.occurred_at
        if e.occurred_at > rec["last"]:
            rec["last"] = e.occurred_at
        if not rec["category"]:
            rec["category"] = (e.raw or {}).get("category")

    out = passthrough[:]
    for (emp, domain, bucket), rec in buckets.items():
        s = rec["sample"]
        raw = dict(s.raw or {})
        raw["category"] = rec["category"]
        raw["visit_count"] = rec["count"]
        out.append(CanonicalEvent(
            occurred_at=bucket, employee_id=emp, device_id=s.device_id,
            category="WEB", action="VISIT", target_type="URL",
            target_value=domain, count=rec["count"], raw=raw))
    return out
