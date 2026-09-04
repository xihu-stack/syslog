# -*- coding: utf-8 -*-
"""AI域名定性扫描(2026-09-04治本①: 规则召回天花板=字典覆盖率)。

漏报复盘实锤: should_trigger硬门控只认字典/模式,字典外求职渠道(各公司挂在
主域的careers子域、小众ATS站)白天纯浏览=窗口不产生=AI永远看不到。本模块把
"新域名定性"交给AI: 每小时捞近3天字典外WEB域名,一次LLM调用批量归类,结果
落domain_classes表;dicts.risk_class()字典未命中后读该缓存——AI说是招聘求职/
网盘,同类事件下次直接按风险域名送判。规则表从静态枚举变成AI喂养的活表,
人工字典/白名单仍在最高优先级,AI只填空白。

正常办公/系统流量也缓存(防每轮重扫烧调用),只是risk_class返回None。
LLM不可达时不更新domain_scan_last,下一轮自动重试。
"""
import json
import re
from datetime import timedelta

import llm_client
from db import DomainClassRow, EventRow, Session, bj_now, write_lock
import dicts

BATCH = 30            # 每轮最多定性域名数(一次LLM调用)
LOOKBACK_DAYS = 3     # 捞最近几天的WEB事件聚合域名
ALLOWED_RISK = set(dicts.RISK_TIER)          # 招聘求职/网盘云盘/个人邮箱/...
ALLOWED_SAFE = {"正常办公", "系统流量", "未知"}  # 缓存但risk_class=None

PROMPT = """你是内网行为审计系统的域名分类器。对列出的每个域名判断类别,只能从以下选一个:
招聘求职(招聘网站/各公司招聘页/ATS求职平台)、网盘/云盘(个人网盘/文件中转站)、个人邮箱、远程控制(远程控制工具)、代码外发(代码托管平台)、微信文件助手(微信传文件通道)、AI助手(AI对话/助手服务)、正常办公(工作/开发/办公/搜索/资讯/学习类网站)、系统流量(系统更新/CDN/遥测/广告等机器流量)。
依据域名本身与页面标题样本判断,拿不准选"正常办公"。
只输出JSON数组,每项 {"domain":"...","label":"...","reason":"10字内理由"},不要输出其他内容。

"""


def _collect_candidates():
    """近N天WEB事件聚合 → 未定性候选 [(domain, hits, users, titles)] 按热度倒序。
    python侧聚合(raw.domain在JSON列里,SQLite聚合写不来);yield_per流式防全表进内存。"""
    since = bj_now() - timedelta(days=LOOKBACK_DAYS)
    agg = {}
    s = Session()
    try:
        q = s.query(EventRow).filter(
            EventRow.occurred_at >= since, EventRow.category == "WEB").yield_per(3000)
        for e in q:
            raw = e.raw if isinstance(e.raw, dict) else {}
            dom = str(raw.get("domain") or e.target_value or "").lower().strip()
            dom = dom.split("/")[0].split(":")[0]
            if not dom or "." not in dom or len(dom) < 5:
                continue
            h = agg.setdefault(dom, {"n": 0, "emps": set(), "titles": []})
            h["n"] += 1
            h["emps"].add(e.employee_id)
            t = str(raw.get("app_title") or raw.get("title") or "").strip()
            if t and len(h["titles"]) < 2:
                h["titles"].append(t[:40])
    finally:
        s.close()

    wl = [w.lower() for w in (dicts.get("risk_whitelist_domains") or [])]
    wd = [w.lower() for w in (dicts.get("work_domains") or [])]
    out = []
    for dom, h in agg.items():
        if dicts.ai_dom_label(dom) is not None:   # 已定性(含正常办公,防重扫)
            continue
        if dicts.risk_class(dom):                 # 人工字典/子域模式已覆盖
            continue
        if dicts._ASSET_CDN_RE.search(dom):
            continue                              # CDN包装的资产拉取
        if dom.count(".") == 3 and all(x.isdigit() for x in dom.split(".")):
            continue                              # IP直连
        if any(dom == w or dom.endswith("." + w) for w in wl + wd):
            continue                              # 白名单/已知工作域
        if dom.split(".")[0] in dicts._SLACK_INFRA_HINT or \
                any(dom.startswith(p) or p in dom for p in dicts._SLACK_SDK_HINT):
            continue                              # 遥测/埋点机器流量
        out.append((dom, h["n"], len(h["emps"]), h["titles"]))
    out.sort(key=lambda x: -x[1])
    return out


def _parse_items(text):
    """模型输出 → [{"domain","label","reason"}]。llm_client.extract_json只吃
    对象(verdict schema),这里要数组: 直接截[]段json.loads,失败逐项正则兜底。"""
    t = llm_client.strip_think(text or "")
    t = re.sub(r"```(?:json)?\s*", "", t).replace("```", "")
    items = []
    s, e = t.find("["), t.rfind("]")
    if s != -1 and e > s:
        try:
            items = json.loads(t[s:e + 1])
        except json.JSONDecodeError:
            pass
    if not items:
        for m in re.finditer(
                r'\{"domain"\s*:\s*"([^"]+)"[^{}]*?"label"\s*:\s*"([^"]+)"'
                r'(?:[^{}]*?"reason"\s*:\s*"([^"]*)")?', t):
            items.append({"domain": m.group(1), "label": m.group(2), "reason": m.group(3) or ""})
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        d = str(it.get("domain") or "").lower().strip()
        lab = str(it.get("label") or "").strip()
        if not d or not lab:
            continue
        if lab not in ALLOWED_RISK and lab not in ALLOWED_SAFE:
            lab = "未知"                          # 词表外标签: 缓存住不重扫,不冒险当风险
        out.append({"domain": d, "label": lab, "reason": str(it.get("reason") or "")[:60]})
    return out


def scan_new_domains():
    """主入口(syslog_recv每小时钩子调用,也可手动跑)。返回摘要dict。"""
    cands = _collect_candidates()[:BATCH]
    res = {"candidates": len(cands), "classified": 0, "risk_n": 0, "risk_samples": ""}
    if not cands:
        dicts.set_setting("domain_scan_last", bj_now().isoformat())
        return res

    lines = [f'{d}(访问{h}次/{u}人,标题: {"; ".join(t) or "无"})' for d, h, u, t in cands]
    msg = llm_client.chat(
        [{"role": "user", "content": PROMPT + "\n".join(lines)}],
        max_tokens=3000, timeout=240)
    items = [it for it in _parse_items(msg) if it["domain"] in {c[0] for c in cands}]
    hits = {c[0]: c[1] for c in cands}
    now = bj_now()
    with write_lock:
        s = Session()
        try:
            for it in items:
                r = s.get(DomainClassRow, it["domain"])
                if r:
                    r.label, r.reason, r.source = it["label"], it["reason"], "ai"
                    r.hits, r.updated_at = hits.get(it["domain"], r.hits or 0), now
                else:
                    s.add(DomainClassRow(domain=it["domain"], label=it["label"],
                                         reason=it["reason"], source="ai",
                                         hits=hits.get(it["domain"], 0), updated_at=now))
            s.commit()
        finally:
            s.close()
    for it in items:                              # 锁外同步进程缓存(幂等)
        dicts.set_ai_dom(it["domain"], it["label"])
    dicts.set_setting("domain_scan_last", now.isoformat())

    risk = [it for it in items if it["label"] in ALLOWED_RISK]
    res.update(classified=len(items), risk_n=len(risk),
               risk_samples="; ".join(f'{it["domain"]}:{it["label"]}' for it in risk)[:200])
    return res


if __name__ == "__main__":
    print(scan_new_domains())
