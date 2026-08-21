"""员工行为时间线(2026-08-21): WEB+DOC+SEARCH 按时间混排,双源统一。

这是"以人为中心"的核心消费方式: 不再分开看网页/文档/搜索,
而是一个人的一天/一周从早到晚干了什么,一目了然。
"""
from __future__ import annotations

from datetime import timedelta

from db import Session, EventRow, bj_now
import dicts


def employee_timeline(emp: str, days: int = 7, limit: int = 2000) -> list:
    s = Session()
    try:
        since = bj_now() - timedelta(days=days)
        evs = (s.query(EventRow)
               .filter(EventRow.employee_id == emp,
                       EventRow.occurred_at >= since)
               .order_by(EventRow.occurred_at.desc())
               .limit(limit).all())
        # 按天采样: 每天最多取80条,保证7天都有数据(不是只取最近500条全是今天的)
        from collections import defaultdict
        by_day = defaultdict(list)
        for e in evs:
            if e.occurred_at:  # None occurred_at的跳过
                by_day[e.occurred_at.date()].append(e)
        sampled = []
        for day_evs in by_day.values():
            sampled.extend(day_evs[:80])
        sampled.sort(key=lambda e: e.occurred_at, reverse=True)
        out = []
        for e in sampled:
            t = e.occurred_at.strftime("%m-%d %H:%M")
            raw = e.raw or {}
            if e.category == "WEB":
                d = (raw.get("domain") or "").lower()
                rc = dicts.risk_class(d)
                title = (raw.get("title") or "").strip()[:40]
                if rc:
                    out.append({"t": t, "type": "web_risk", "icon": "🌐",
                                "text": f"访问 {d} ×{e.count or 1}" + (f" 《{title}》" if title and title != "-" else ""),
                                "risk": rc})
                # 非风险WEB跳过(太多,时间线只保留有意义的)
            elif e.category == "DOC":
                act_map = {"OPEN": "打开", "READ": "读取", "MODIFY": "修改", "DELETE": "删除",
                           "COPY": "复制", "RENAME": "重命名", "SEND": "📤发送", "UPLOAD": "📤上传",
                           "PRINT": "🖨打印", "ARCHIVE": "📦压缩", "DOWNLOAD": "⬇下载"}
                act = act_map.get(e.action, e.action)
                fname = (e.target_value or "")[:44]
                dest = (raw.get("dest_path") or "").split("/")[0][:30]
                size_mb = (e.size_bytes or 0) / 1048576
                size_str = f" ({size_mb:.1f}MB)" if size_mb >= 0.1 else ""
                ch = raw.get("channel") or ""
                dest_str = f" → {dest}" if dest and e.action in ("SEND", "UPLOAD") else (f" [{ch}]" if ch and ch != "LOCAL" else "")
                out.append({"t": t, "type": "doc_" + (e.action.lower() if e.action else "unknown"), "icon": "📄",
                            "text": f"{act} {fname}{size_str}{dest_str}",
                            "risk": dicts.risk_class(dest) if dest else None})
            elif e.category == "SEARCH" and e.target_value:
                kw = e.target_value[:40]
                out.append({"t": t, "type": "search", "icon": "🔍",
                            "text": f"搜索「{kw}」",
                            "risk": None})
        # 按时间正序(旧→新,符合阅读习惯)
        out.reverse()
        return out
    finally:
        s.close()
