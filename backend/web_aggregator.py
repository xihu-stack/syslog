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
    # 基础设施/后台流量(2026-08-28全量审计: 60人高分窗口被系统流量灌满,占窗口事件
    # 大头却无风险语义): Win11小组件新闻流msn.cn / M365遥测svc / Windows推送更新 /
    # 登录配置端点 / VSCode后台同步 / 阿里SDK遥测 / QQ心跳代理 / 广告交易平台 /
    # md-prod-simcon(51人共用的Azure端点)
    "msn.cn", "wns.notify", "onecdn", "ms-acdc", "msidentity.com", "windowsupdate",
    "vscode-cdn", "vscode-sync", "adblockplus", "mqtt.aliyuncs", "log.aliyuncs",
    "jsonproxy", "rubiconproject", "config.edge.skype", "md-prod-simcon",
]
# 噪声资源扩展名（URL 路径后缀）
NOISE_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2",
             ".svg", ".ttf", ".otf", ".map", ".webp")


def _wl_skip(d: str) -> bool:
    """公司白名单域不滤: ±180s网页上传邻近推断依赖窗口内的白名单浏览事件
    (如*.svc.cloud.microsoft虽属遥测族,但匹配cloud.microsoft白名单后缀,
    滤掉会砍断'上传邻近公司M365通道'的推断锚点)。"""
    try:
        import dicts
        for w in dicts.get("risk_whitelist_domains") or []:
            if d == w or d.endswith("." + w):
                return True
    except Exception:
        pass
    return False


def is_noise(domain: str, url: str) -> bool:
    d = (domain or "").lower()
    # 非域名占位(2026-08-28审计): sangfor把协议/应用名塞进domain字段
    # (snmp 1727条/未识别应用 1012条出现在高分窗口),不是网站访问
    if not d or "." not in d:
        return True
    # file:///浏览器本地打开(2026-08-31审计): 本地路径被塞进domain字段入库,
    # 不是网站访问;本地文件读取DOC侧READ已有证据,域名口径剔除
    if d.startswith("file:"):
        return True
    if _wl_skip(d):
        return False
    # websocket传输帧域(ws.chatgpt.com等): 每条消息/心跳一条日志,把"挂了30分钟
    # 网页"记成"访问数千次"(2026-08-28审计单人单日7326条),频次档/跨天计数全被
    # 灌水——传输帧不是访问;主域(chatgpt.com等)事件保留,使用信号不丢
    if d.startswith("ws.") or d.startswith("ab.chatgpt."):
        return True
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
                            "category": (e.raw or {}).get("category"), "sample": e,
                            "titles": [], "urls": []}
        rec = buckets[key]
        rec["count"] += 1
        if e.occurred_at < rec["first"]:
            rec["first"] = e.occurred_at
        if e.occurred_at > rec["last"]:
            rec["last"] = e.occurred_at
        if not rec["category"]:
            rec["category"] = (e.raw or {}).get("category")
        # 桶内语义证据留存(2026-08-24): 聚合曾只留第一条的标题/URL——登录页标题
        # 盖过上传页标题、filehelper"打开vs上传"的路径证据丢失
        _t = ((e.raw or {}).get("title") or "").strip()
        if _t and _t != "-" and _t not in rec["titles"] and len(rec["titles"]) < 2:
            rec["titles"].append(_t)
        _u = (e.target_value or "")
        if _u.count("/") >= 2 and _u not in rec["urls"] and len(rec["urls"]) < 2:
            rec["urls"].append(_u.split("?")[0][-60:])

    out = passthrough[:]
    for (emp, domain, bucket), rec in buckets.items():
        s = rec["sample"]
        raw = dict(s.raw or {})
        raw["category"] = rec["category"]
        raw["visit_count"] = rec["count"]
        if rec["titles"]:
            raw["titles"] = rec["titles"]
            raw["title"] = rec["titles"][-1]  # 最新标题(操作页)优先于首条(登录页)
        if rec["urls"]:
            raw["url_samples"] = rec["urls"]
        if rec["first"] != rec["last"]:
            raw["first_at"] = rec["first"].isoformat()
            raw["last_at"] = rec["last"].isoformat()
        out.append(CanonicalEvent(
            occurred_at=bucket, employee_id=emp, device_id=s.device_id,
            category="WEB", action="VISIT", target_type="URL",
            target_value=domain, count=rec["count"], source=getattr(s,'source',''), raw=raw))
    return out
