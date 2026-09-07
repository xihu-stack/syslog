# -*- coding: utf-8 -*-
"""员工日级AI语义门控(2026-09-04治本②): 零研判员工的漏报巡检。

漏报根因另一半: should_trigger硬门控下,信号不足的员工整天不产生任何窗口
(字典外搜索词"社保停缴"、中性域名上的面经文章、低频组合),AI永远看不到
这些人。本模块每天凌晨对"昨天零研判"的活跃员工做一次轻量AI巡检:
全天活动摘要(浏览TOP+标题/搜索/文档操作/时段) → 一次LLM调用判断是否有
被规则漏掉的风险信号 → 有则写 unknown 桩 verdict(intent=unknown,
ai_participated=0),既有 sweep补判机制(pipeline.run_detection)1小时内
自动捞走做完整深判——锚点/评分/告警/豁免全部走标准路径,本模块只做路由。

判定原则证据优先(拿不准=false): 巡检只负责"该不该再看一眼",深判权在
标准研判链;宁漏勿冤,防巡检自己变成误报源。
"""
from collections import Counter
from datetime import timedelta

import llm_client
from db import EventRow, Session, VerdictRow, bj_now, write_lock
import detector
import dicts

MAX_CALLS = 100000  # 沉默人群全查(2026-09-07用户拍板: 砍掉原60人上限,零研判员工
                    # 次日100%巡检)。凌晨串行轻扫~10s/人,百人级公司全天沉默量可承受;上限仅防极端值
MIN_EVENTS = 3      # 低于此事件量的员工不值得巡检
SCORE_GATE = 50     # 巡检分低于此不立桩(弱联想放过)

PROMPT = """你是企业行为审计系统的"日级漏报巡检员"。规则引擎昨天对这名员工没有产生任何研判
(未命中任何字典域名/关键词/频次阈值),但规则有盲区: 字典外的求职网站、未收录的关键词
组合、低频但敏感的操作。下面是他全天活动摘要,请判断是否漏掉了风险信号:
- job_seeking: 求职或离职前兆(招聘/职位页面、面经、投简历、社保停缴、竞业赔偿等)
- data_exfiltration: 疑似数据外发(向网盘/个人邮箱/微信/未知网页上传公司文件)
- policy_violation: 访问公司禁止的网站或远程控制工具
判定原则——证据优先: 摘要里有明确具体证据(页面标题/搜索词/外发记录)才suspect=true;
纯娱乐浏览、正常工作访问、弱联想一律false;拿不准=false。
只输出JSON: {"suspect":true,"intent":"job_seeking","score":65,"evidence":"引用摘要原文"}
"""


def _priority(s, d0, d1):
    """昨天的沉默员工: 有事件但零verdict。按(文档外发操作>凌晨活动>事件量)排序。"""
    from pipeline import _ignored_employees
    judged = {e for (e,) in s.query(VerdictRow.employee_id).filter(
        VerdictRow.window_start >= d0, VerdictRow.window_start < d1).all()}
    n, doc, off = Counter(), set(), Counter()
    for e in s.query(EventRow).filter(
            EventRow.occurred_at >= d0, EventRow.occurred_at < d1).yield_per(3000):
        emp = e.employee_id
        n[emp] += 1
        if e.category == "DOC" and e.action in ("SEND", "UPLOAD", "PRINT", "BURN"):
            doc.add(emp)
        if e.occurred_at and detector._is_off_hours(e.occurred_at):
            off[emp] += 1
    ignored = _ignored_employees()
    cands = [emp for emp, c in n.items()
             if c >= MIN_EVENTS and emp not in judged and emp not in ignored]
    cands.sort(key=lambda emp: (emp in doc, off[emp], n[emp]), reverse=True)
    return cands


def _digest(evs):
    """员工全天事件 → 巡检摘要。标题是漏报最强信号(中性域名上的招聘页),
    每个TOP域名带最长的页面标题;搜索词全保——字典外关键词只能靠AI语义识别。"""
    web, web_title, searches, docs, hrs = Counter(), {}, [], [], set()
    off_n = 0
    for e in evs:
        raw = e.raw if isinstance(e.raw, dict) else {}
        if e.occurred_at:
            hrs.add(e.occurred_at.hour)
            if detector._is_off_hours(e.occurred_at):
                off_n += 1
        if e.category == "WEB":
            d = str(raw.get("domain") or e.target_value or "").lower().split("/")[0]
            if d:
                web[d] += e.count or 1
                t = str(raw.get("app_title") or raw.get("title") or "").strip()
                if t and len(t) > len(web_title.get(d, "")):
                    web_title[d] = t
        elif e.category == "SEARCH" and e.target_value:
            searches.append(str(e.target_value)[:30])
        elif e.category == "DOC":
            dest = dicts.dest_host(raw)[:28]
            docs.append(f"{e.action}『{(e.target_value or '')[:24]}』→{dest or '未识别'}")
    lines = [f"事件{len(evs)}条(凌晨{off_n}条) 活跃{min(hrs)}-{max(hrs)}时"
             if hrs else f"事件{len(evs)}条"]
    lines.append("浏览TOP: " + "; ".join(
        f"{d}×{n}《{web_title.get(d, '')[:26]}》".rstrip("《》")
        for d, n in web.most_common(14)))
    if searches:
        lines.append("搜索: " + "; ".join(searches[:12]))
    if docs:
        lines.append("文档操作: " + "; ".join(docs[:8]))
    return "\n".join(lines)[:1600]


def _pick_hashes(evs):
    """桩verdict的代表性事件哈希(sweep按此重建窗口): 搜索/文档全保,
    WEB按域聚合取TOP20域各≤5条(优先带标题的)。总上限300。"""
    searches = [e for e in evs if e.category == "SEARCH"][:40]
    docs = [e for e in evs if e.category == "DOC"][:60]
    by_dom = {}
    for e in evs:
        if e.category != "WEB":
            continue
        raw = e.raw if isinstance(e.raw, dict) else {}
        d = str(raw.get("domain") or e.target_value or "").lower().split("/")[0]
        if d:
            by_dom.setdefault(d, []).append(e)
    web = []
    for d, lst in sorted(by_dom.items(), key=lambda kv: -len(kv[1]))[:20]:
        titled = [x for x in lst if str((x.raw or {}).get("app_title")
                                        or (x.raw or {}).get("title") or "").strip()]
        web.extend((titled or lst)[:5])
    return [e.event_hash for e in (searches + docs + web)[:300] if e.event_hash]


def _parse(text):
    """{"suspect","intent","score","evidence"} —— extract_json的兜底正则只认
    verdict schema,这里自己截大括号段+专属兜底。"""
    import json
    import re
    t = llm_client.strip_think(text or "")
    t = re.sub(r"```(?:json)?\s*", "", t).replace("```", "")
    r = {}
    s, e = t.find("{"), t.rfind("}")
    if s != -1 and e > s:
        try:
            r = json.loads(t[s:e + 1])
        except json.JSONDecodeError:
            r = {}
    if not isinstance(r, dict):
        r = {}
    if "suspect" not in r:
        m = re.search(r'"suspect"\s*:\s*(true|false)', t)
        r["suspect"] = m and m.group(1) == "true"
    m = re.search(r'"score"\s*:\s*(\d+)', t)
    if m:
        r["score"] = int(m.group(1))
    m = re.search(r'"intent"\s*:\s*"([^"]+)"', t)
    if m:
        r["intent"] = m.group(1)
    m = re.search(r'"evidence"\s*:\s*"([^"]*)"', t)
    if m:
        r["evidence"] = m.group(1)
    return r


def run_day_gate() -> dict:
    """主入口(syslog_recv每天hour>=2调用一次)。返回摘要;LLM全灭时
    不写daygate_last,下一小时自动重试。"""
    d1 = bj_now().replace(hour=0, minute=0, second=0, microsecond=0)
    d0 = d1 - timedelta(days=1)
    res = {"candidates": 0, "called": 0, "ok": 0, "suspects": 0, "stubs": []}
    s = Session()
    try:
        cands = _priority(s, d0, d1)[:MAX_CALLS]
        res["candidates"] = len(cands)
        for emp in cands:
            evs = s.query(EventRow).filter(EventRow.employee_id == emp,
                                           EventRow.occurred_at >= d0,
                                           EventRow.occurred_at < d1
                                           ).order_by(EventRow.occurred_at).all()
            if len(evs) < MIN_EVENTS:
                continue
            res["called"] += 1
            _cal = ""
            try:  # 口径统一注入(2026-09-04): 与研判/domain_scan同源
                import casebase
                _cal = casebase.caliber_text()
            except Exception:
                pass
            try:
                msg = llm_client.chat(
                    [{"role": "user", "content": PROMPT + _cal + "\n" + _digest(evs)}],
                    max_tokens=300, timeout=120)
            except Exception:
                continue  # 单人失败不拖累整轮;全灭时ok=0不落last,下小时重试
            r = _parse(msg)
            if not r:
                continue
            res["ok"] += 1
            if not r.get("suspect") or int(r.get("score") or 0) < SCORE_GATE:
                continue
            res["suspects"] += 1
            hashes = _pick_hashes(evs)
            if not hashes:
                continue
            wstart, wend = evs[0].occurred_at, evs[-1].occurred_at
            with write_lock:
                ss = Session()
                try:
                    if not ss.query(VerdictRow).filter_by(
                            employee_id=emp, window_start=wstart).first():
                        ss.add(VerdictRow(
                            employee_id=emp, device=evs[0].device_id,
                            window_start=wstart, window_end=wend,
                            intent="unknown", risk_score=0,
                            explanation=f"[日级门控] 规则未触发但巡检发现疑似{r.get('intent')}"
                                        f"({str(r.get('evidence'))[:60]}),待sweep深判",
                            ai_participated=0, event_hashes=hashes, model="daygate"))
                        ss.commit()
                        res["stubs"].append(f"{emp}:{r.get('intent')}{r.get('score')}")
                finally:
                    ss.close()
        if res["ok"] > 0 or res["candidates"] == 0:
            dicts.set_setting("daygate_last", bj_now().strftime("%Y%m%d"))
    finally:
        s.close()
    return res


if __name__ == "__main__":
    print(run_day_gate())
