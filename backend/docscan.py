"""IPG 文档行为 AI 深扫(本地 DeepSeek-R1,每周一次 + 手动触发)。

挖掘目标(2026-08-20):
  1. 外发模式: 谁在把什么文件发往哪里(微信/网页上传/打印),组合敏感度人眼看不过来;
  2. 敏感文件识别: 生物药行业文件名(试验方案/报告/项目编号)超出固定关键词表,
     让 R1 提炼"本公司的敏感文件命名特征"并建议新增敏感词;
  3. 异常组合: 非工作时段批量外发、离职前兆(简历修改+招聘+外发)等跨信号模式。

输出: findings(人可读结论) + suggest_keywords/suggest_domains(建议,不自动生效,
人工在字典页采纳) → 存 settings + webhook 通知。
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import timedelta

from db import Session, EventRow, bj_now
import dicts
import llm_client

PROMPT = """你是企业数据安全分析师。基于 IP-Guard 文档操作日志摘要(近7天,已按员工聚合),输出 JSON:
{"findings": [{"employee": "...", "severity": "high|mid|low", "desc": "一句话:什么文件发到了哪里,为何可疑"}],
 "suggest_keywords": ["建议新增的敏感文件名关键词(本公司语境,如试验/项目编号特征)"],
 "suggest_domains": ["建议关注的外发目的地域名"]}
要求: findings 只报真实外发(SEND/UPLOAD/PRINT)且有实质风险的,按严重度排序最多8条;
没有就空数组,不要编造。desc 必须含文件名+目的地。只输出 JSON。"""


def run_doc_scan(days: int = 7) -> dict:
    s = Session()
    try:
        since = bj_now() - timedelta(days=days)
        evs = s.query(EventRow).filter(EventRow.source == "ipguard",
                                        EventRow.occurred_at >= since).all()
        by_emp = defaultdict(list)
        for e in evs:
            if e.category == "DOC" and e.action in ("SEND", "UPLOAD", "PRINT", "BURN", "COPY"):
                by_emp[e.employee_id].append(e)
        if not by_emp:
            return {"ok": False, "error": "近7天无IPG文档操作数据"}
        lines = [f"共{len(by_emp)}人有文档操作,以下为外发/打印类:"]
        for emp, lst in sorted(by_emp.items(), key=lambda x: -len(x[1]))[:40]:
            acts = defaultdict(list)
            for e in lst:
                dest = ((e.raw or {}).get("dest_path") or "")[:50] or "-"
                hour = e.occurred_at.hour
                night = "(夜)" if hour < 7 or hour >= 22 else ""
                acts[f"{e.action}{night}"].append(f"{(e.target_value or '')[:40]} → {dest}")
            lines.append(f"[{emp}]")
            for k, items in acts.items():
                for it in items[:6]:
                    lines.append(f"  {k} {it}")
                if len(items) > 6:
                    lines.append(f"  …共{len(items)}条")
        digest = "\n".join(lines)[:12000]
    finally:
        s.close()

    try:
        raw = llm_client.chat([{"role": "system", "content": PROMPT},
                               {"role": "user", "content": digest}],
                              max_tokens=4000, timeout=600,
                              model=llm_client.smart_model() or None)
        txt = llm_client.strip_think(raw)
        i, depth, j = txt.find("{"), 0, -1
        for k2, ch in enumerate(txt):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    j = k2
                    break
        result = json.loads(txt[i:j + 1]) if i >= 0 and j > i else {"findings": [], "error": "解析失败"}
    except Exception as ex:
        result = {"findings": [], "error": f"R1调用失败: {str(ex)[:120]}"}

    result["ts"] = bj_now().isoformat()
    result["employees"] = len(by_emp)
    dicts.set_setting("ipg_doc_scan", json.dumps(result, ensure_ascii=False))

    # webhook 通知高分发现
    try:
        url = dicts.get_setting("notify_webhook", "")
        highs = [f for f in result.get("findings", []) if f.get("severity") == "high"]
        if url and highs:
            body = json.dumps({"msgtype": "text", "text": {"content":
                "📋 IPG文档深扫(周): " + " | ".join(
                    f"{f['employee']}: {f.get('desc', '')[:60]}" for f in highs[:3])}},
                ensure_ascii=False).encode()
            import urllib.request as _u
            _u.urlopen(_u.Request(url, data=body,
                                  headers={"Content-Type": "application/json"}), timeout=5)
    except Exception:
        pass
    return result
