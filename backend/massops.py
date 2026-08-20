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
            day = lst[0].occurred_at.strftime("%m-%d")
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
                           severity="crit" if risk >= 76 else "high", risk_score=risk,
                           summary=summary, dedup_key=key,
                           window_start=lst[-1].occurred_at, created_at=bj_now(), status="NEW"))
            created += 1
            print(f"[massops] {emp} {day} 删除{len(lst)}次/{len(files)}文件 -> {risk}分", flush=True)
        s.commit()
        return {"checked": len(by_emp), "created": created, "skipped": skipped}
    finally:
        s.close()
