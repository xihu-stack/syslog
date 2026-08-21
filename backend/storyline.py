"""离职风险故事线(2026-08-21 加强项5): 把分散信号串成时间叙事。

数据源(近30天, 按员工聚合):
  - 求职类研判/告警 + 招聘站访问(按天)
  - 大量删除告警
  - 文档外发(SEND/UPLOAD到网络, 按天+目的地+文件名样例)
  - 简历类文档操作(文件名语义由R1判断,不做关键词)
  - 搜索关注(搜索词历史)
  - 节律突变(深夜活跃天数)
触发: ≥2类不同信号才进入R1;输出 {stage: 观察|关注|预警|高危, story, signals}。
存储 settings 'risk_stories'(emp -> 最新故事), 画像页/大屏可读。
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import timedelta

from db import Session, EventRow, VerdictRow, AlertRow, bj_now
import dicts
import llm_client

PROMPT = """你是企业员工风险分析师。输入是某员工近30天的多源信号时间摘要(浏览/文档/搜索/告警)。
请把信号串成时间叙事,输出 JSON:
{"stage": "观察|关注|预警|高危",
 "story": "按时间先后叙述行为演变(150字内),只陈述信号事实+你的推断,推断要标明'推断';",
 "signals": ["信号1一句话", "信号2一句话"]}
判断口径: 单一信号=观察; 招聘+文档/搜索组合=关注; 再加删除或外发上升=预警; 全链条(招聘+简历+删除+外发)=高危。
没有明确信号就 stage=观察, story 写"暂无组合信号"。只输出JSON。"""


def build_stories(days: int = 30, min_signals: int = 2) -> dict:
    s = Session()
    try:
        since = bj_now() - timedelta(days=days)
        # 信号收集
        sig = defaultdict(lambda: defaultdict(list))  # emp -> 类型 -> [条目]
        for v in s.query(VerdictRow).filter(VerdictRow.window_start >= since).all():
            if v.intent == "job_seeking" and (v.risk_score or 0) >= 50:
                sig[v.employee_id]["招聘访问"].append(f"{str(v.window_start)[5:11]} {v.risk_score}分")
        for a in s.query(AlertRow).filter(AlertRow.created_at >= since).all():
            if a.scenario == "mass_delete":
                sig[a.employee_id]["大量删除"].append(str(a.created_at)[5:11])
            elif a.scenario == "data_exfiltration":
                sig[a.employee_id]["外发告警"].append(f"{str(a.window_start)[5:11]} {a.risk_score}分")
        for e in s.query(EventRow).filter(EventRow.source == "ipguard",
                                           EventRow.occurred_at >= since).all():
            if e.category == "DOC" and e.action in ("SEND", "UPLOAD") \
                    and (e.raw or {}).get("channel") not in (None, "", "LOCAL"):
                dest = ((e.raw or {}).get("dest_path") or "").split("/")[0][:30]
                sig[e.employee_id]["网络外发"].append(
                    f"{str(e.occurred_at)[5:11]} {(e.target_value or '')[:36]}→{dest}")
            elif e.category == "SEARCH" and e.target_value:
                sig[e.employee_id]["搜索"].append(f"{str(e.occurred_at)[5:11]} {e.target_value[:20]}")
        # 每人信号条目裁剪
        cands = {}
        for emp, kinds in sig.items():
            kinds = {k: v[-8:] for k, v in kinds.items()}
            if len(kinds) >= min_signals:
                cands[emp] = kinds
        results = {}
        for emp, kinds in list(cands.items())[:15]:  # R1调用限流
            digest = f"员工: {emp}(近{days}天)\n" + "\n".join(
                f"[{k}] " + "; ".join(v[-6:]) for k, v in kinds.items())
            try:
                raw = llm_client.chat([{"role": "system", "content": PROMPT},
                                       {"role": "user", "content": digest[:8000]}],
                                      max_tokens=800, timeout=600,
                                      model=llm_client.smart_model() or None)
                txt = llm_client.strip_think(raw)
                i = txt.find("{")
                r = json.loads(txt[i:txt.rfind("}") + 1]) if i >= 0 else {}
                r["ts"] = bj_now().isoformat()
                results[emp] = r
            except Exception as ex:
                results[emp] = {"stage": "未知", "story": f"生成失败:{str(ex)[:60]}",
                                "signals": list(kinds.keys())}
        dicts.set_setting("risk_stories", json.dumps(results, ensure_ascii=False))
        return {"candidates": len(cands), "stories": len(results),
                "stages": {e: r.get("stage") for e, r in results.items()}}
    finally:
        s.close()
