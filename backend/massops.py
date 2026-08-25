"""行为聚合告警(2026-08-20用户要求): 谁 在某时间段 大量 干了什么 → AI按5W汇总成告警。

首批场景: 大量删除文件 = 离职前清理前兆(结合文件名判断)。
规则: 单日非噪声删除 ≥15 个且 ≥8 个不同文件 → 触发;40+ 升高危。
Qwen 按文件名列表写5W说明(谁/何时/通过什么/删了什么/属什么问题);
缓存/系统文件已排除(detector.is_noise_doc),只统计用户文档区的真实删除。
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import timedelta

from db import Session, EventRow, AlertRow, bj_now
import dicts
import detector

PROMPT = """你是企业行为安全分析师。输入: 某员工一天内删除的文件清单(IP-Guard,已排除系统/缓存文件)。
输出 JSON: {"summary": "按5W写一段: 谁(用输入的员工名)在何时(日期+时段)通过什么(本机删除)删了什么(数量+代表性文件名3-5个+类型归纳,如『试验报告类/合同类/个人文件类』),属于什么问题(大量删除=疑似离职前清理/数据销毁前兆,结合文件名特征判断更像工作清理还是敏感清理)"}
只输出JSON,summary一段话120字内。"""


def scan_mass_deletes() -> dict:
    s = Session()
    try:
        since = bj_now() - timedelta(days=1)
        evs = s.query(EventRow).filter(EventRow.source == "ipguard",
                                        EventRow.category == "DOC",
                                        EventRow.action == "DELETE",
                                        EventRow.occurred_at >= since).all()
        by_emp = defaultdict(list)
        for e in evs:
            if detector.is_noise_doc(e):
                continue
            by_emp[e.employee_id].append(e)
        created = skipped = 0
        for emp, lst in by_emp.items():
            files = sorted({(e.target_value or "").strip() for e in lst if (e.target_value or "").strip()})
            if len(lst) < 15 or len(files) < 8:
                continue
            day = lst[0].occurred_at.strftime("%Y-%m-%d")
            key = f"{emp}|mass_delete|{day}"
            if s.query(AlertRow).filter_by(dedup_key=key).first():
                skipped += 1
                continue
            hours = sorted({e.occurred_at.hour for e in lst})
            digest = f"员工: {emp}\n日期: {lst[0].occurred_at.strftime('%Y-%m-%d')} 时段{hours[0]}-{hours[-1]}时\n共删除{len(lst)}次/{len(files)}个不同文件:\n" + "\n".join(files[:40])
            summary = ""
            try:
                import llm_client
                raw = llm_client.chat([{"role": "system", "content": PROMPT},
                                       {"role": "user", "content": digest[:6000]}],
                                      max_tokens=500, timeout=120)
                txt = llm_client.strip_think(raw)
                i = txt.find("{")
                summary = (json.loads(txt[i:txt.rfind("}") + 1]) or {}).get("summary", "") if i >= 0 else ""
            except Exception:
                pass
            if not summary:
                sample = "、".join(files[:4])
                summary = f"{emp}在{day}通过本机删除{len(lst)}次/{len(files)}个文件(如{sample}),大量删除属疑似离职前清理,需核查"
            risk = 80 if len(lst) >= 40 else 70
            s.add(AlertRow(employee_id=emp, scenario="mass_delete",
                           severity="CRITICAL" if risk >= 76 else "HIGH", risk_score=risk,
                           summary=summary, dedup_key=key,
                           window_start=lst[-1].occurred_at, created_at=bj_now(), status="NEW"))
            created += 1
            print(f"[massops] {emp} {day} 删除{len(lst)}次/{len(files)}文件 -> {risk}分", flush=True)
        s.commit()
        # ---- 外发量聚合(蚂蚁搬家检测,2026-08-21): 单日≥15次或≥50MB ----
        created2 = scan_mass_exfil(s)
        return {"checked": len(by_emp), "created": created + created2, "skipped": skipped}
    finally:
        s.close()


def scan_mass_exfil(s) -> int:
    """外发量聚合: 单日非白名单SEND/UPLOAD≥15次 或 总量≥50MB → 告警。"""
    # 邻近白名单推断(2026-08-24鄢荣梅案例): IPG对网页上传(msedgewebview2.exe等)
    # 不记录目标域名只标NETWORK,空目的地被当"非白名单"误计入蚂蚁搬家——
    # 按同时刻(±3分钟)浏览的公司白名单域名判定为Teams/M365等公司通道
    _wl = [w.lower() for w in dicts.get("risk_whitelist_domains") or []]
    webs = defaultdict(list)
    for w in s.query(EventRow).filter(EventRow.category == "WEB",
                                       EventRow.occurred_at >= bj_now() - timedelta(days=1)).all():
        d = ((w.raw or {}).get("domain") or "").lower()
        if d:
            webs[w.employee_id].append((w.occurred_at, d))
    for k in webs:
        webs[k].sort()

    def _nearby(emp, ts):
        """±3分钟浏览域名: 返回(白名单命中, 非白名单域名样例)"""
        wl_hit, doms = False, []
        for t, d in webs.get(emp, ()):
            if abs((t - ts).total_seconds()) > 180:
                continue
            if any(d == x or d.endswith("." + x) for x in _wl):
                wl_hit = True
            elif d not in doms:
                doms.append(d)
        return wl_hit, doms

    by_emp = defaultdict(list)
    _inferred = {}
    for e in s.query(EventRow).filter(EventRow.source == "ipguard",
                                       EventRow.occurred_at >= bj_now() - timedelta(days=1),
                                       EventRow.action.in_(("SEND", "UPLOAD"))).all():
        dest = ((e.raw or {}).get("dest_path") or "").strip().lower()
        if dest.startswith(("http:", "https:")):
            _p = dest.split("/")
            dest = _p[2] if len(_p) > 2 else dest
        else:
            dest = dest.split("/")[0]
        if dest and any(dest == w or dest.endswith("." + w) for w in _wl):
            continue
        if not dest:  # 空目的地: 邻近推断
            wl_hit, doms = _nearby(e.employee_id, e.occurred_at)
            if wl_hit:
                continue  # 公司通道(Teams/M365传附件),不计入外发
            if doms:
                _inferred[(e.employee_id, e.id)] = doms[0][:36]
        by_emp[e.employee_id].append(e)
    created = 0
    for emp, lst in by_emp.items():
        total_mb = sum((e.size_bytes or 0) for e in lst) / 1048576
        if len(lst) < 15 and total_mb < 50:
            continue
        day = lst[0].occurred_at.strftime("%Y-%m-%d")
        key = f"{emp}|mass_exfil|{day}"
        if s.query(AlertRow).filter_by(dedup_key=key).first():
            continue
        # 样例文件名放宽到48字符(2026-08-24用户反馈: HXN-9004...zip被截成.zi);
        # 目的地为空时回退到通道名,不再留悬空箭头
        def _dest(e):
            d = ((e.raw or {}).get("dest_path") or "").strip()
            if d.startswith(("http:", "https:")):
                _p = d.split("/")
                d = _p[2] if len(_p) > 2 else d
            else:
                d = d.split("/")[0]
            if d:
                return d[:36]
            inf = _inferred.get((e.employee_id, e.id))
            if inf:
                return inf + "(同期浏览)"
            ch = (e.raw or {}).get("channel") or ""
            return (ch + "·未识别目的地") if ch and ch != "LOCAL" else "网络通道·未识别目的地"
        sample = "; ".join(f"『{(e.target_value or '未命名文件')[:48]}』→{_dest(e)}" for e in lst[:4])
        # 触发模式区分(2026-08-24用户反馈: 单次1.78GB也叫"蚂蚁搬家"矛盾)——
        # ≥15次=高频小批量(蚂蚁搬家), 少量但体量大=单次/少量大体量外发
        mode = "高频小批量·蚂蚁搬家模式" if len(lst) >= 15 else "少量大体量外发"
        big = max(((e.size_bytes or 0) for e in lst), default=0)
        big_txt = f",单文件最大{big / 1048576:.0f}MB" if big > 50 * 1048576 else ""
        risk = 85 if len(lst) >= 30 or total_mb >= 100 else 75
        s.add(AlertRow(employee_id=emp, scenario="mass_exfil",
                       severity="CRITICAL" if risk >= 76 else "HIGH", risk_score=risk,
                       summary=f"{emp}在{day}向非白名单目的地累计外发{len(lst)}次、共{total_mb:.1f}MB{big_txt}({mode})。样例: {sample}",
                       dedup_key=key, window_start=lst[-1].occurred_at, created_at=bj_now(), status="NEW"))
        created += 1
        print(f"[massops-exfil] {emp} {day} 外发{len(lst)}次/{total_mb:.0f}MB -> {risk}分", flush=True)
    s.commit()
    return created
