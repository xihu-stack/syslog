"""周报自动生成(2026-08-21): R1综述本周风险+TOP变化+建议,webhook推送。

数据源: 本周告警/研判/故事线/风险榜/效率 —— 全部程序化统计后R1写结论。
挂载: 每周五17:00(工作时间结束前推送,管理层周一早上看)。
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import timedelta
from db import Session, AlertRow, VerdictRow, EventRow, bj_now
import dicts
import llm_client

PROMPT = """你是企业安全周报撰写人。输入是本周(近7天)的多维安全数据摘要。
输出 JSON: {"headline": "一句话概括本周态势",
 "sections": [{"title": "板块名", "body": "2-3句话分析,数字必须精确"}],
 "top_risks": ["风险最高的3个人,各一句话(名字+场景+分数+关键行为)"],
 "recommendations": ["2-3条具体建议"]}
板块建议: 离职风险/数据外发/行为异常/效率概况。只输出JSON。"""


def gen_weekly() -> dict:
    s = Session()
    try:
        since = bj_now() - timedelta(days=7)
        # 告警统计
        alerts = s.query(AlertRow).filter(AlertRow.created_at >= since).all()
        al_scen = Counter(a.scenario for a in alerts)
        al_new = sum(1 for a in alerts if a.status == "NEW")
        # 研判统计
        verdicts = s.query(VerdictRow).filter(VerdictRow.window_start >= since).count()
        # 事件量
        events = s.query(EventRow).filter(EventRow.occurred_at >= since).count()
        # 外发统计
        sends = s.query(EventRow).filter(
            EventRow.source == "ipguard", EventRow.occurred_at >= since,
            EventRow.action.in_(("SEND", "UPLOAD"))).count()
        # 故事线
        try:
            stories = json.loads(dicts.get_setting("risk_stories") or "{}")
        except Exception:
            stories = {}
        hi_stories = {e: x for e, x in stories.items() if x.get("stage") in ("高危", "预警")}
        # 风险榜
        try:
            from riskboard import risk_board
            board = risk_board()[:5]
        except Exception:
            board = []
        digest = (f"本周数据(近7天):\n"
                  f"告警: {len(alerts)}条(待处理{al_new}), 分布{dict(al_scen)}\n"
                  f"研判: {verdicts}次, 事件: {events}条, 外发动作: {sends}次\n"
                  f"风险榜TOP5: {[(x['employee'], x['score'], x['stage']) for x in board]}\n"
                  f"故事线高危/预警: {list(hi_stories.keys())[:8]}\n")
        # 效率top3
        try:
            from api import efficiency
            eff = efficiency()
            top = sorted(eff, key=lambda x: -(x.get("slack_avg") or 0))[:3]
            digest += f"摸鱼TOP3: {[(x['employee'], x['slack_avg']) for x in top]}\n"
        except Exception:
            pass
    finally:
        s.close()

    try:
        raw = llm_client.chat([{"role": "system", "content": PROMPT},
                               {"role": "user", "content": digest[:6000]}],
                              max_tokens=2000, timeout=600,
                              model=llm_client.smart_model() or None)
        txt = llm_client.strip_think(raw)
        i = txt.find("{")
        result = json.loads(txt[i:txt.rfind("}") + 1]) if i >= 0 else {}
    except Exception as ex:
        result = {"headline": f"周报生成失败: {str(ex)[:60]}", "sections": [], "top_risks": [], "recommendations": []}
    result["ts"] = bj_now().isoformat()
    dicts.set_setting("weekly_report", json.dumps(result, ensure_ascii=False))

    # webhook推送
    try:
        url = dicts.get_setting("notify_webhook", "")
        if url and result.get("headline"):
            body = json.dumps({"msgtype": "text", "text": {"content":
                f"📋 安全周报: {result['headline']}\n" +
                "\n".join(f"• {r}" for r in result.get("top_risks", [])[:3])}},
                ensure_ascii=False).encode()
            import urllib.request as _u
            _u.urlopen(_u.Request(url, data=body, headers={"Content-Type": "application/json"}), timeout=5)
    except Exception:
        pass
    return result


# ---------- 导出 ----------
def export_profile_csv(emp: str) -> str:
    """单人画像+故事线+告警 CSV。"""
    import csv, io as _io
    s = Session()
    try:
        out = _io.StringIO()
        w = csv.writer(out)
        w.writerow(["类型", "时间", "场景/动作", "分数", "状态", "说明"])
        for a in s.query(AlertRow).filter_by(employee_id=emp).order_by(AlertRow.risk_score.desc()).all():
            w.writerow(["告警", str(a.window_start)[:16], a.scenario, a.risk_score, a.status, (a.summary or "")[:80]])
        for v in s.query(VerdictRow).filter_by(employee_id=emp).order_by(VerdictRow.window_start.desc()).limit(50).all():
            w.writerow(["研判", str(v.window_start)[:16], v.intent, v.risk_score, "", (v.explanation or "")[:80]])
        try:
            stories = json.loads(dicts.get_setting("risk_stories") or "{}")
            if emp in stories:
                st = stories[emp]
                w.writerow(["故事线", st.get("ts", "")[:10], st.get("stage", ""), "", "", (st.get("story") or "")[:120]])
        except Exception:
            pass
        return out.getvalue()
    finally:
        s.close()


# ---------- 深夜工作模式 ----------
def night_worker_list() -> list:
    """深夜(22-7点)经常活跃的人,含近7天深夜事件分布。"""
    s = Session()
    try:
        since = bj_now() - timedelta(days=7)
        by_emp = Counter()
        doms_by_emp = {}
        for e in s.query(EventRow).filter(
                EventRow.occurred_at >= since).all():
            h = e.occurred_at.hour
            if h < 7 or h >= 22:
                by_emp[e.employee_id] += 1
                d = ((e.raw or {}).get("domain") or "").lower()
                if d and not dicts.risk_class(d) and not d.startswith(("wns.", "st.", "update.", "auto.")):
                    doms_by_emp.setdefault(e.employee_id, Counter())[d] += 1
        result = []
        for emp, cnt in by_emp.most_common(20):
            if cnt < 20:
                break
            top_d = [d for d, _ in doms_by_emp.get(emp, Counter()).most_common(3)]
            result.append({"employee": emp, "night_events": cnt,
                           "top_domains": top_d})
        return result
    finally:
        s.close()


# ---------- 跨人同名文件 ----------
def cross_person_files() -> list:
    """同一文件名出现在≥2人的DOC事件中 → 内部流转。"""
    s = Session()
    try:
        since = bj_now() - timedelta(days=7)
        file_emps = {}
        for e in s.query(EventRow).filter(
                EventRow.source == "ipguard", EventRow.occurred_at >= since,
                EventRow.category == "DOC",
                EventRow.action.in_(("SEND", "UPLOAD", "COPY"))).all():
            fname = (e.target_value or "").strip().lower()
            if len(fname) < 5 or fname.startswith(("sendphotoes", "preferences", "~$")):
                continue
            file_emps.setdefault(fname, set()).add(e.employee_id)
        shared = [(f, sorted(emps)) for f, emps in file_emps.items() if len(emps) >= 2]
        shared.sort(key=lambda x: -len(x[1]))
        return [{"file": f, "people": emps, "count": len(emps)} for f, emps in shared[:20]]
    finally:
        s.close()
