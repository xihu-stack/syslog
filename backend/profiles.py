"""行为画像构建：从 events 滚动统计每员工基线，喂给 LLM 做偏离判断。

v1 用轻量统计（活跃时段/日均量/常用通道/常接触关键词），不上重型 ML。
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from statistics import median

from db import EventRow, ProfileRow, Session, bj_now, json_field, write_lock
import dicts  # 敏感词表改为从字典配置读取

LOOKBACK_DAYS = 30


def _events_for(session, emp):
    since = bj_now() - timedelta(days=LOOKBACK_DAYS)
    return (session.query(EventRow)
            .filter(EventRow.employee_id == emp, EventRow.occurred_at >= since)
            .all())


def global_common_domains(session, min_users_ratio=0.3, min_count=5):
    """全局通用域名：超过 min_users_ratio 比例用户访问过的域名。
    这些域名对任何人都不算'陌生'（微软云/CDN/搜索引擎等）。
    风险类域名(招聘/网盘等)排除——多人访问不代表正常,不能稀释风险判断(2026-08-19)。"""
    from collections import Counter
    from sqlalchemy import func as _f
    total_users = session.query(EventRow.employee_id).distinct().count()
    if total_users < 3:
        return set()
    threshold = max(2, int(total_users * min_users_ratio))
    # 统计每个域名被多少不同用户访问
    dom = json_field(EventRow.raw, 'domain')
    rows = session.query(
        dom,
        _f.count(_f.distinct(EventRow.employee_id))
    ).filter(
        EventRow.category == 'WEB',
        dom.isnot(None)
    ).group_by(dom).all()
    return {r[0] for r in rows if r[0] and r[1] >= threshold and not dicts.risk_class(r[0])}


def compute_profile(rows) -> dict:
    hours = Counter()
    per_day = Counter()
    web_classes = Counter()
    domains = Counter()
    channels, actions, keywords = set(), set(), set()
    _rc = {}  # risk_class按域名缓存(域名仅数千个,逐行全模式匹配太慢)
    # ---- 画像四维(2026-08-21 IPG数据完善后加强) ----
    import re as _re
    doc_types = Counter()        # ①文档行为: 文件类型
    project_codes = Counter()    # ①文档行为: 项目编号(业务版图)
    send_ch = Counter()          # ①④外发通道偏好
    sends_by_day = Counter()     # ④外发趋势(按天)
    search_topics = Counter()    # ③搜索关注点
    day_first, day_last = {}, {}  # ②节律: 每日首末事件小时
    for r in rows:
        hours[r.occurred_at.hour] += 1
        d0 = r.occurred_at.date()
        per_day[d0] += 1
        h = r.occurred_at.hour
        if d0 not in day_first or h < day_first[d0]:
            day_first[d0] = h
        if d0 not in day_last or h > day_last[d0]:
            day_last[d0] = h
        ch = (r.raw or {}).get("channel")
        if ch:
            channels.add(ch)
        if r.category == "WEB":
            d = (r.raw or {}).get("domain")
            if d:
                # 风险类域名永不计入个人基线(2026-08-19用户口径): 招聘/网盘/邮箱等
                # 即使天天访问也不构成"正常"——高频恰恰是进行中风险信号,基线只描述
                # 正常办公习惯。否则AI看到"在其基线内"会降权误判。
                if d not in _rc:
                    _rc[d] = dicts.risk_class(d)
                if not _rc[d]:
                    domains[d] += 1
            dc = (r.raw or {}).get("domain_class")
            if dc and dc != "other":
                web_classes[dc] += 1
        elif r.category == "DOC":
            tv = r.target_value or ""
            mext = _re.search(r"\.([A-Za-z0-9]{1,6})$", tv)
            if mext:
                doc_types[mext.group(1).lower()] += 1
            for code in _re.findall(r"[A-Z]{2,6}[-_]\d{2,6}", tv)[:3]:
                project_codes[code] += 1
            if r.action in ("SEND", "UPLOAD", "PRINT", "BURN"):
                dest = ((r.raw or {}).get("dest_path") or "").split("/")[0][:40]
                send_ch[f"{r.action}:{dest or (r.raw or {}).get('channel') or 'LOCAL'}"] += 1
                sends_by_day[d0.isoformat()] += 1
        elif r.category == "SEARCH" and r.target_value:
            search_topics[r.target_value.strip()[:24]] += 1
        actions.add(r.action)
        for k in dicts.get("sensitive_keywords"):
            if k in (r.target_value or ""):
                keywords.add(k)
    daily = list(per_day.values())
    starts = sorted(day_first.values())
    ends = sorted(day_last.values())
    late_days = sum(1 for d, h in day_first.items() if h < 7)
    return {
        "active_days": len(per_day),
        "active_hours_top": [h for h, _ in hours.most_common(8)],
        "daily_doc_op_median": int(median(daily)) if daily else 0,
        "daily_doc_op_max": max(daily) if daily else 0,
        "channels_used": sorted(channels),
        "web_classes": dict(web_classes),
        "common_domains": [d for d, _ in domains.most_common(20)],
        "actions_seen": sorted(actions),
        "usual_keywords": sorted(keywords),
        "sample_count": len(rows),
        # 四维新画像(旧数据无此键时消费方用get兜底)
        "doc_types": dict(doc_types.most_common(8)),
        "project_codes": dict(project_codes.most_common(8)),
        "send_channels": dict(send_ch.most_common(6)),
        "sends_by_day": dict(sorted(sends_by_day.items())[-14:]),
        "search_topics": [k for k, _ in search_topics.most_common(10)],
        "rhythm": {"start_median": starts[len(starts) // 2] if starts else None,
                   "end_median": ends[len(ends) // 2] if ends else None,
                   "late_night_days": late_days},
    }


def baseline_for(session, employee_id: str, cutoff) -> dict:
    """该员工 cutoff 之前的历史行为基线——用于研判当前窗口是否偏离。"""
    rows = (session.query(EventRow).filter(EventRow.employee_id == employee_id,
            EventRow.occurred_at < cutoff).all())
    return compute_profile(rows)


def summarize_for_llm(p: dict):
    """把画像压缩成【结构化基线】给 LLM。

    返回 None 表示冷启动（样本不足）—— 由调用方决定如何喂全局基线。
    结构化输出：样本量/置信度 + 常规时段 + 日均量 + 常用域名集（让 AI 判断当前域名是否陌生）。
    """
    if not p or p.get("sample_count", 0) < 15:  # <15样本不足以建个人基线→冷启动走全局参照
        return None
    n = p["sample_count"]
    tier = "成熟" if n >= 50 else "较薄"
    hrs = p["active_hours_top"]
    hrange = f"{min(hrs)}-{max(hrs)}点" if hrs else "未知"
    doms = p.get("common_domains", [])[:8]
    dom_txt = "、".join(doms) if doms else "无明显常用域名"
    ch = "/".join(p.get("channels_used", [])) or "未记录"
    # 四维新画像压缩(2026-08-21): 让AI看到文档版图/节律/外发偏好/搜索关注
    dt = p.get("doc_types") or {}
    pc = p.get("project_codes") or {}
    sc = p.get("send_channels") or {}
    rh = p.get("rhythm") or {}
    st = p.get("search_topics") or []
    sd = p.get("sends_by_day") or {}
    extra = []
    if dt:
        extra.append(f"常处理文件类型: {'、'.join(f'{k}×{v}' for k, v in list(dt.items())[:5])}")
    if pc:
        extra.append(f"常接触项目编号: {'、'.join(list(pc)[:6])}")
    if sc:
        extra.append(f"外发习惯: {'、'.join(f'{k}×{v}' for k, v in list(sc.items())[:4])}")
    if sd:
        vals = list(sd.values())
        extra.append(f"外发趋势(近{len(vals)}天,最多{max(vals)}次/天)")
    if rh.get("start_median") is not None:
        extra.append(f"节律: 约{rh['start_median']}点开始/{rh['end_median']}点结束,深夜活跃{rh.get('late_night_days', 0)}天")
    if st:
        extra.append(f"近期搜索关注: {'、'.join(st[:5])}")
    extra_txt = ("；".join(extra)) if extra else ""
    return (f"【个人基线·{tier}(样本{n})】常规活跃时段 {hrange}；"
            f"日均事件量~{p.get('daily_doc_op_median', 0)}(峰值{p.get('daily_doc_op_max', 0)})；"
            f"常用通道 {ch}；常用域名：{dom_txt}。"
            + (f"{extra_txt}。" if extra_txt else "")
            + "判断要点：当前窗口出现【不在常用集内】的【高危类别】域名=异常；仅域名多不异常。"
            + ("外发/文档行为相对上述习惯的突变=重点。" if extra else ""))


def global_summary(session) -> str:
    """全局参照（每轮研判算一次，喂给所有窗口的 AI）：让 AI 区分'普遍行为' vs '个人异常'。

    冷启动用户没有个人基线时，以此作为参照系，避免 AI 因'陌生'误判。"""
    total_users = session.query(EventRow.employee_id).distinct().count()
    return (f"【全局参照】全公司约 {total_users or '?'} 名员工。"
            f"上班时段(8-20点)普遍访问搜索引擎/银行/IT/新闻/政府等正常行业网站，属常规办公；"
            f"高危类别(远程控制/网盘/个人邮箱/招聘/微信传输) 全局仅极少数人使用，出现即需重点关注。"
            f"仅'陌生域名数量多'不构成风险（几乎每人每天上百个新域名）。")


def build_profiles() -> int:
    """全量重建所有员工画像，返回员工数。按 employee_id 唯一键 upsert。"""
    with write_lock:  # 与研判 _flush 串行写，避免写锁互等报 database is locked
        s = Session()
        try:
            emps = [r[0] for r in s.query(EventRow.employee_id).distinct()]
            now = datetime.utcnow()
            for emp in emps:
                p = compute_profile(_events_for(s, emp))
                existing = s.query(ProfileRow).filter_by(employee_id=emp).first()
                if existing:
                    existing.as_of = now
                    existing.payload = p
                else:
                    s.add(ProfileRow(employee_id=emp, as_of=now, payload=p))
            s.commit()
            return len(emps)
        finally:
            s.close()
