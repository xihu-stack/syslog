"""FastAPI 后端：AI 判断/告警/事件/员工/导入/反馈 API + 托管前端静态页。

启动:  python api.py   然后浏览器打开 http://127.0.0.1:8000
"""
import os
import shutil
import tempfile

from fastapi import Body, FastAPI, File, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, func

from db import (AlertRow, EventRow, ExceptionRow, FeedbackRow, ProfileRow, Session, VerdictRow, bj_now, init_db, json_field)
import pipeline
import profiles
import dicts
import syslog_recv

app = FastAPI(title="IP-Guard 员工行为分析")
init_db()
# 若上次启用了 syslog，自动恢复监听
if dicts.get_setting("syslog_enabled", "0") == "1":
    try:
        syslog_recv.start(dicts.get_setting("syslog_host", "0.0.0.0"),
                          int(dicts.get_setting("syslog_port", "8514")))
    except Exception as e:
        print("syslog 自启失败:", e)

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


# ---------------- 工具 ----------------

def _event_dict(e: EventRow) -> dict:
    return {
        "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
        "employee": e.employee_id, "device": e.device_id,
        "category": e.category, "action": e.action,
        "target_value": e.target_value, "size_bytes": e.size_bytes,
        "source": e.source or "",
        "channel": (e.raw or {}).get("channel"),
        "application": (e.raw or {}).get("application"),
    }


def _verdict_dict(s: Session, r: VerdictRow) -> dict:
    events = []
    for h in (r.event_hashes or []):
        e = s.query(EventRow).filter_by(event_hash=h).first()
        if e:
            events.append(_event_dict(e))
    return {
        "id": r.id, "employee": r.employee_id, "device": r.device,
        "window_start": r.window_start.isoformat() if r.window_start else None,
        "window_end": r.window_end.isoformat() if r.window_end else None,
        "intent": r.intent, "deviation": r.deviation, "risk_score": r.risk_score,
        "explanation": r.explanation, "channels": r.channels,
        "ai_participated": bool(r.ai_participated), "events": events,
    }


# ---------------- API ----------------

@app.get("/api/stats")
def stats():
    from datetime import datetime, timedelta
    s = Session()
    try:
        now = bj_now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return {
            "events": s.query(EventRow).count(),
            "events_today": s.query(EventRow).filter(EventRow.occurred_at >= today_start).count(),
            "verdicts": s.query(VerdictRow).count(),
            "alerts": s.query(AlertRow).count(),
            "alerts_open": s.query(AlertRow).filter(AlertRow.status != "CLOSED").count(),
            "employees": s.query(EventRow.employee_id).filter(EventRow.occurred_at >= today_start).distinct().count(),
        }
    finally:
        s.close()


@app.get("/api/verdicts")
def list_verdicts(employee: str | None = None, limit: int = 100):
    s = Session()
    try:
        q = s.query(VerdictRow).order_by(desc(VerdictRow.window_start))
        if employee:
            q = q.filter(VerdictRow.employee_id == employee)
        return [_verdict_dict(s, r) for r in q.limit(limit).all()]
    finally:
        s.close()


@app.get("/api/alerts")
def list_alerts(severity: str | None = None, limit: int = 100):
    s = Session()
    try:
        q = s.query(AlertRow).order_by(desc(AlertRow.risk_score), desc(AlertRow.created_at))
        if severity:
            q = q.filter(AlertRow.severity == severity)
        return [{
            "id": r.id, "employee": r.employee_id, "scenario": r.scenario,
            "severity": r.severity, "risk_score": r.risk_score, "summary": r.summary,
            "status": r.status,
            "window_start": r.window_start.isoformat() if r.window_start else None,
            "verdict_id": r.verdict_id,
        } for r in q.limit(limit).all()]
    finally:
        s.close()


@app.get("/api/employees/{emp}")
def employee(emp: str):
    s = Session()
    try:
        p = s.query(ProfileRow).filter_by(employee_id=emp).first()
        evs = (s.query(EventRow).filter_by(employee_id=emp)
               .order_by(desc(EventRow.occurred_at)).limit(50).all())
        # 风险行为: 外发通道/招聘/远程控制域名访问 或 文档写/外发动作(最近300条里筛,取30)
        import detector
        risk_evs = []
        for e in (s.query(EventRow).filter_by(employee_id=emp)
                  .order_by(desc(EventRow.occurred_at)).limit(300).all()):
            dom = (e.raw or {}).get("domain") or ""
            if (e.category == "WEB" and dicts.risk_class(dom)) or \
               (e.category == "DOC" and e.action in detector.WRITE_ACTIONS):
                risk_evs.append(e)
            if len(risk_evs) >= 30:
                break
        vs = (s.query(VerdictRow).filter_by(employee_id=emp)
              .order_by(desc(VerdictRow.window_start)).limit(20).all())
        return {
            "employee": emp,
            "profile": p.payload if p else None,
            "profile_summary": (profiles.summarize_for_llm(p.payload) if p else None) or "样本不足，按通用可疑度判断",
            "events": [_event_dict(e) for e in evs],
            "risk_events": [{
                "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
                "category": e.category, "action": e.action, "target_value": e.target_value,
                "domain": (e.raw or {}).get("domain") or "",
                "risk_class": dicts.risk_class((e.raw or {}).get("domain") or ""),
                "source": e.source or "",
            } for e in risk_evs],
            "verdicts": [{"window_start": v.window_start.isoformat() if v.window_start else None,
                          "intent": v.intent, "risk_score": v.risk_score,
                          "explanation": v.explanation} for v in vs],
        }
    finally:
        s.close()


@app.get("/api/computers")
def computers():
    """按计算机(身份)合并：事件数/告警数/最高风险/最近活动——用于计算机视图与历史研判。"""
    s = Session()
    try:
        ev = (s.query(EventRow.employee_id, func.count(EventRow.id), func.max(EventRow.occurred_at))
              .group_by(EventRow.employee_id).all())
        vr = {r[0]: r[1] for r in
              s.query(VerdictRow.employee_id, func.max(VerdictRow.risk_score)).group_by(VerdictRow.employee_id).all()}
        al = {r[0]: r[1] for r in
              s.query(AlertRow.employee_id, func.count(AlertRow.id)).group_by(AlertRow.employee_id).all()}
        out = [{"computer": e, "event_count": c, "last_seen": (t.isoformat() if t else None),
                "max_risk": vr.get(e), "alert_count": al.get(e, 0)} for e, c, t in ev]
        out.sort(key=lambda x: -(x["max_risk"] or 0))
        return out
    finally:
        s.close()


@app.post("/api/ingest")
async def ingest(file: UploadFile = File(...)):
    """上传 xlsx/csv → 批量导入 → 建画像 → 异步启动研判（立即返回，前端轮询进度）。"""
    suffix = os.path.splitext(file.filename or "")[1] or ".xlsx"
    tmp = os.path.join(tempfile.gettempdir(), f"ipg_upload{suffix}")
    with open(tmp, "wb") as f:
        shutil.copyfileobj(file.file, f)
    n = pipeline.ingest_file(tmp)
    profiles.build_profiles()
    st = pipeline.start_detection()  # 单飞异步研判，不阻塞请求
    return {"imported": n, "detection": st}


@app.post("/api/run")
def run():
    """对库内已有事件异步启动研判（单飞）。"""
    profiles.build_profiles()
    return pipeline.start_detection()


@app.get("/api/detect/status")
def detect_status():
    """轮询研判进度。"""
    return pipeline.detection_status()


@app.get("/api/exceptions")
def list_exceptions():
    """查询豁免列表（已确认正常的用户行为）。"""
    from datetime import datetime
    s = Session()
    try:
        rows = s.query(ExceptionRow).filter(
            (ExceptionRow.expires_at.is_(None)) | (ExceptionRow.expires_at > datetime.utcnow())
        ).all()
        return [{"id": r.id, "employee": r.employee_id, "signal_type": r.signal_type,
                 "reason": r.reason, "expires_at": r.expires_at.isoformat() if r.expires_at else None}
                for r in rows]
    finally:
        s.close()


@app.delete("/api/exceptions/{eid}")
def delete_exception(eid: int):
    """删除豁免（恢复告警）。"""
    s = Session()
    try:
        r = s.get(ExceptionRow, eid)
        if r:
            s.delete(r)
            s.commit()
        return {"ok": True}
    finally:
        s.close()


@app.post("/api/rejudge")
def rejudge():
    """清空旧研判 + 重置水位，全量重研判（修复模型/prompt 后重跑）。"""
    return pipeline.rejudge_all()


@app.post("/api/feedback")
def feedback(alert_id: int, label: str, reason: str = "", signal_type: str = "", expires_days: int = 0):
    """标记告警 TP/FP。FP 可带原因+信号类型创建豁免（下次同类不再告警）。"""
    if label not in ("TP", "FP"):
        raise HTTPException(400, "label 必须是 TP 或 FP")
    from datetime import datetime, timedelta
    from db import ExceptionRow
    s = Session()
    try:
        s.add(FeedbackRow(alert_id=alert_id, label=label, reason=reason))
        a = s.get(AlertRow, alert_id)
        if a:
            a.status = "CONFIRMED" if label == "TP" else "FP"
            if label == "FP" and signal_type:
                exp = datetime.utcnow() + timedelta(days=expires_days) if expires_days > 0 else None
                s.add(ExceptionRow(employee_id=a.employee_id, signal_type=signal_type,
                                   reason=reason, expires_at=exp))
        s.commit()
        return {"ok": True}
    finally:
        s.close()


@app.put("/api/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, status: str = "TRIAGING"):
    """更新告警状态：NEW/TRIAGING/CONFIRMED/FP/CLOSED。"""
    if status not in ("NEW", "TRIAGING", "CONFIRMED", "FP", "CLOSED"):
        raise HTTPException(400, "无效状态")
    s = Session()
    try:
        a = s.get(AlertRow, alert_id)
        if not a:
            raise HTTPException(404, "告警不存在")
        a.status = status
        s.commit()
        return {"ok": True, "status": status}
    finally:
        s.close()


@app.post("/api/verdicts/{vid}/confirm")
def verdict_confirm(vid: int):
    """通过研判ID确认告警（自动找到对应alert）。"""
    s = Session()
    try:
        a = s.query(AlertRow).filter_by(verdict_id=vid).first()
        if not a:
            return {"ok": False, "error": "未找到对应告警"}
        a.status = "CONFIRMED"
        s.commit()
        return {"ok": True}
    finally:
        s.close()


@app.post("/api/verdicts/{vid}/false_positive")
def verdict_false_positive(vid: int, reason: str = "误报", signal_type: str = "", expires_days: int = 0):
    """通过研判ID标记误报 + 创建豁免。"""
    from datetime import datetime, timedelta
    from db import ExceptionRow
    s = Session()
    try:
        a = s.query(AlertRow).filter_by(verdict_id=vid).first()
        if not a:
            return {"ok": False, "error": "未找到对应告警"}
        a.status = "FP"
        s.add(FeedbackRow(alert_id=a.id, label="FP", reason=reason))
        if signal_type:
            exp = datetime.utcnow() + timedelta(days=expires_days) if expires_days > 0 else None
            s.add(ExceptionRow(employee_id=a.employee_id, signal_type=signal_type,
                               reason=reason, expires_at=exp))
        s.commit()
        return {"ok": True}
    finally:
        s.close()


# ---------------- 字典配置（后台可增删改）----------------
@app.get("/api/dicts")
def get_dicts():
    return dicts.all_dicts()

@app.put("/api/dicts/{name}")
def update_dict(name: str, values: list = Body(...)):
    if name not in dicts.DEFAULTS:
        raise HTTPException(400, f"未知字典: {name}")
    dicts.set_dict(name, values)
    return {"ok": True, "name": name, "count": len(values)}


# ---------------- 应用配置（LLM / Syslog，后台在线修改）----------------
@app.get("/api/config")
def get_config():
    base = dicts.get_setting("llm_base_url") or os.environ.get("LLM_BASE_URL", "")

    def mask(k):
        return (k[:6] + "***" + k[-4:]) if k and len(k) > 12 else ("***" if k else "")

    qk = dicts.get_setting("llm_qwen_key") or os.environ.get("LLM_QWEN_KEY") or os.environ.get("LLM_API_KEY", "")
    dk = dicts.get_setting("llm_deepseek_key") or os.environ.get("LLM_DEEPSEEK_KEY", "")
    return {
        "llm_base_url": base,
        "llm_active": dicts.get_setting("llm_active", "qwen"),
        "qwen": {"model": dicts.get_setting("llm_qwen_model") or os.environ.get("LLM_QWEN_MODEL", "Qwen3-32B"),
                 "key_masked": mask(qk), "has_key": bool(qk)},
        "deepseek": {"model": dicts.get_setting("llm_deepseek_model") or os.environ.get("LLM_DEEPSEEK_MODEL", "deepseek"),
                     "base_url": dicts.get_setting("llm_deepseek_base_url") or "",
                     "key_masked": mask(dk), "has_key": bool(dk)},
        "syslog_enabled": dicts.get_setting("syslog_enabled", "0"),
        "syslog_host": dicts.get_setting("syslog_host", "0.0.0.0"),
        "syslog_port": dicts.get_setting("syslog_port", "8514"),
        "notify_webhook": dicts.get_setting("notify_webhook", ""),
    }


@app.put("/api/config")
def set_config(body: dict = Body(...)):
    for k in ("llm_base_url", "llm_active", "llm_qwen_model", "llm_deepseek_model",
              "llm_deepseek_base_url", "syslog_enabled", "syslog_host", "syslog_port", "notify_webhook"):
        if body.get(k) is not None:
            dicts.set_setting(k, str(body[k]))
    if body.get("qwen_key"):
        dicts.set_setting("llm_qwen_key", body["qwen_key"])
    if body.get("deepseek_key"):
        dicts.set_setting("llm_deepseek_key", body["deepseek_key"])
    return {"ok": True}


@app.post("/api/syslog/start")
def syslog_start():
    host = dicts.get_setting("syslog_host", "0.0.0.0")
    port = int(dicts.get_setting("syslog_port", "8514"))
    syslog_recv.start(host, port)
    dicts.set_setting("syslog_enabled", "1")
    return syslog_recv.status()


@app.post("/api/syslog/stop")
def syslog_stop():
    syslog_recv.stop()
    dicts.set_setting("syslog_enabled", "0")
    return syslog_recv.status()


@app.get("/api/syslog/status")
def syslog_status():
    return syslog_recv.status()


@app.get("/api/system/stats")
def system_stats():
    """系统运行状态：日志量/研判量/数据来源/告警状态/管线健康。"""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import func as _f
    s = Session()
    try:
        now = bj_now()
        today_start = (now - timedelta(hours=now.hour, minutes=now.minute, seconds=now.second, microseconds=now.microsecond))
        yesterday_start = today_start - timedelta(days=1)
        week_start = today_start - timedelta(days=7)

        # 按来源统计：今日/昨日/近7天/总量
        def src_count(since):
            # source=''（历史遗留未标来源，实为深信服上网日志）与 'sangfor' 合并为一组，
            # 否则 r[0] or "sangfor" 会让两者落到同一 dict key、后者覆盖前者，丢掉空来源那批数。
            src_expr = _f.coalesce(_f.nullif(EventRow.source, ""), "sangfor")
            rows = s.query(src_expr, _f.count(EventRow.id)).filter(
                EventRow.occurred_at >= since).group_by(src_expr).all()
            return {r[0]: r[1] for r in rows}

        src_today = src_count(today_start)
        src_yesterday = src_count(yesterday_start)
        src_week = src_count(week_start)
        src_total = src_count(datetime(2000, 1, 1))

        # 事件量
        ev_today = sum(src_today.values())
        ev_yesterday = sum(src_yesterday.values())
        ev_week = sum(src_week.values())
        ev_total = s.query(EventRow).count()

        # 研判量（今日/昨日/总量）
        vd_today = s.query(VerdictRow).filter(VerdictRow.created_at >= today_start).count()
        vd_yesterday = s.query(VerdictRow).filter(
            VerdictRow.created_at >= yesterday_start,
            VerdictRow.created_at < today_start
        ).count()
        vd_total = s.query(VerdictRow).count()
        vd_ai = s.query(VerdictRow).filter(VerdictRow.ai_participated == 1).count()
        vd_fallback = s.query(VerdictRow).filter(VerdictRow.ai_participated == 0).count()

        # 告警（今日/昨日/总量）
        al_today = s.query(AlertRow).filter(AlertRow.created_at >= today_start).count()
        al_yesterday = s.query(AlertRow).filter(
            AlertRow.created_at >= yesterday_start,
            AlertRow.created_at < today_start
        ).count()
        al_total = s.query(AlertRow).count()
        st_rows = s.query(AlertRow.status, _f.count(AlertRow.id)).group_by(AlertRow.status).all()
        alert_status = {r[0]: r[1] for r in st_rows}

        # 豁免
        ex_count = s.query(ExceptionRow).filter(
            (ExceptionRow.expires_at.is_(None)) | (ExceptionRow.expires_at > now)
        ).count()

        # 数据库大小
        import os as _os
        db_path = _os.path.join(_os.path.dirname(__file__), "data", "ipguard.db")
        db_size = _os.path.getsize(db_path) if _os.path.exists(db_path) else 0

        # 去重/降噪统计（总事件中WEB事件比例，估算降噪效果）
        web_total = s.query(EventRow).filter(EventRow.category == "WEB").count()

        # 画像上次全量重建时间（as_of 存的是 utcnow naive UTC，转 epoch 供前端算"X分钟前"）
        _lp = s.query(_f.max(ProfileRow.as_of)).scalar()
        profile_updated_ts = int(_lp.replace(tzinfo=timezone.utc).timestamp()) if _lp else None

        return {
            "events": {
                "today": ev_today, "yesterday": ev_yesterday, "week": ev_week, "total": ev_total,
                "web_ratio": round(web_total / max(ev_total, 1) * 100, 1),
                "emp_yesterday": s.query(EventRow.employee_id).filter(
                    EventRow.occurred_at >= yesterday_start,
                    EventRow.occurred_at < today_start
                ).distinct().count(),
            },
            "sources": {
                "today": src_today, "yesterday": src_yesterday, "week": src_week, "total": src_total,
            },
            "verdicts": {
                "today": vd_today, "yesterday": vd_yesterday, "total": vd_total, "ai": vd_ai, "fallback": vd_fallback,
            },
            "alerts": {
                "today": al_today, "yesterday": al_yesterday, "total": al_total, "status": alert_status,
                "list": [{
                    "employee": r.employee_id, "scenario": r.scenario,
                    "risk_score": r.risk_score, "status": r.status, "summary": r.summary,
                } for r in s.query(AlertRow).order_by(desc(AlertRow.risk_score), desc(AlertRow.created_at)).limit(50).all()],
            },
            "exceptions": ex_count,
            "db_size_mb": round(db_size / 1024 / 1024, 1),
            "employees": s.query(EventRow.employee_id).filter(EventRow.occurred_at >= today_start).distinct().count(),
            "detect": pipeline.detection_status(),
            "syslog": syslog_recv.status(),
            "profile_updated_ts": profile_updated_ts,
        }
    finally:
        s.close()


_eff_cache = {"data": None, "ts": 0}

@app.get("/api/efficiency")
def efficiency():
    """工作效率统计: 每员工工作时段(9-18)摸鱼(视频/社交/购物/资讯/音乐)+在岗天数/时段。"""
    import time
    if _eff_cache["data"] is not None and time.time() - _eff_cache["ts"] < 60:
        return _eff_cache["data"]
    from collections import Counter
    s = Session()
    try:
        rows = s.query(EventRow).filter(EventRow.category == "WEB").all()
        emp = {}
        for e in rows:
            r = emp.setdefault(e.employee_id, {"total": 0, "slack": 0, "cats": Counter(),
                                               "days": set(), "hours": set()})
            r["total"] += 1
            if e.occurred_at:
                r["days"].add(e.occurred_at.date()); r["hours"].add(e.occurred_at.hour)
            cat = dicts.slack_category((e.raw or {}).get("domain") or "")
            if cat and e.occurred_at and 9 <= e.occurred_at.hour < 18:
                r["slack"] += 1; r["cats"][cat] += 1
        out = []
        for k, r in emp.items():
            hours = sorted(r["hours"])
            out.append({"employee": k, "total": r["total"], "slack": r["slack"],
                        "pct": round(r["slack"] / r["total"] * 100) if r["total"] else 0,
                        "cats": dict(r["cats"]), "active_days": len(r["days"]),
                        "hour_min": hours[0] if hours else None, "hour_max": hours[-1] if hours else None})
        out.sort(key=lambda x: -x["pct"])
        _eff_cache["data"] = out; _eff_cache["ts"] = time.time()
        return out
    finally:
        s.close()


@app.get("/api/category_stats")
def category_stats():
    """今日/昨日网站分类（深信服 app 字段）分布。"""
    from datetime import datetime, timedelta
    s = Session()
    try:
        now = bj_now()
        today_start = (now - timedelta(hours=now.hour, minutes=now.minute, seconds=now.second, microseconds=now.microsecond))
        yesterday_start = today_start - timedelta(days=1)

        def cat_count(since, until=None):
            app = json_field(EventRow.raw, 'app')
            q = s.query(app, func.count(EventRow.id)).filter(
                EventRow.category == 'WEB', EventRow.occurred_at >= since)
            if until:
                q = q.filter(EventRow.occurred_at < until)
            rows = q.group_by(app).all()
            return {r[0] or "未识别": r[1] for r in rows if r[0]}

        today = cat_count(today_start)
        yesterday = cat_count(yesterday_start, today_start)
        return {"today": today, "yesterday": yesterday}
    finally:
        s.close()


@app.get("/api/export/alerts")
def export_alerts():
    """导出告警为CSV（安全运营报告用）。"""
    import csv as _csv
    import io as _io
    from fastapi.responses import StreamingResponse
    s = Session()
    try:
        rows = s.query(AlertRow).order_by(desc(AlertRow.risk_score)).all()
        output = _io.StringIO()
        output.write("﻿")
        w = _csv.writer(output)
        w.writerow(["用户", "场景", "严重度", "风险分", "状态", "时间", "说明"])
        SCN = {"job_seeking":"求职离职","data_exfiltration":"数据外发","baseline_deviation":"行为偏离","policy_violation":"违规"}
        for r in rows:
            w.writerow([r.employee_id, SCN.get(r.scenario, r.scenario or ""), r.severity,
                        r.risk_score, r.status, r.window_start.isoformat() if r.window_start else "", r.summary])
        output.seek(0)
        return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                                headers={"Content-Disposition": "attachment; filename=alerts.csv"})
    finally:
        s.close()


# ---------------- AI 问答（LLM 路由 → 查真数据 → LLM 总结）----------------
@app.post("/api/ask")
def ask(body: dict = Body(...)):
    """自然语言查数据: 路由 LLM 选 action → 后端查真数据 → 总结 LLM 回答。"""
    import llm_client
    question = (body.get("question") or "").strip()
    if not question:
        return {"answer": "请输入问题。", "action": "empty"}
    route_sys = ("你是行为分析助手。把用户问题路由到查询动作,只输出 JSON {action, employee, category}。\n"
                 "action: employee_risk(查某员工风险行为) / alerts(告警榜) / slack(摸鱼榜) / attendance(在岗情况) / who_risk(谁访问了某类风险网站) / help(规则/用法说明) / chat(其他闲聊)。\n"
                 "注意: 问【离职/求职/跳槽/找工作】风险 → who_risk + category=招聘(查访问招聘网站的人, 不是看告警)。\n"
                 "employee: 仅 employee_risk 时填员工姓名(从问题提取)。\n"
                 "category: 仅 who_risk 时填, 取值 远程控制/网盘/邮箱/招聘/文件助手 之一(从问题判断是哪类风险)。\n"
                 "只输出 JSON。")
    try:
        raw = llm_client.chat([{"role": "system", "content": route_sys}, {"role": "user", "content": question}],
                              max_tokens=120, timeout=60)
        v = llm_client.extract_json(raw) or {}
    except Exception:
        v = {}
    action = v.get("action") if v.get("action") in ("employee_risk", "alerts", "slack", "attendance", "who_risk", "help", "chat") else "chat"
    employee = (v.get("employee") or "").strip()
    category = (v.get("category") or "").strip()
    if action == "who_risk" and not category:  # LLM 漏填 category 时从问题关键词兜底
        ql = question.lower()
        if "netdisk" in ql or "网盘" in question or "云盘" in question: category = "网盘"
        elif "email" in ql or "邮箱" in question or "mail" in ql: category = "邮箱"
        elif "remote" in ql or "远程" in question or "todesk" in ql: category = "远程控制"
        elif "recruit" in ql or "招聘" in question or "求职" in question: category = "招聘"
        elif "filehelper" in ql or "文件助手" in question or "传输助手" in question: category = "文件助手"
    data_ctx = _ask_query(action, employee, category)
    sum_sys = ("你是企业员工行为分析助手,基于给定真实数据简洁回答用户问题。"
               "只基于数据、不编造;数据不足就直说。中文,要点清晰。")
    user_msg = f"用户问题: {question}\n\n查询数据:\n{data_ctx}" + ("\n\n请基于上述数据回答。" if data_ctx else "\n\n(无相关数据,可自由作答)")
    try:
        ans = llm_client.chat([{"role": "system", "content": sum_sys}, {"role": "user", "content": user_msg}],
                              max_tokens=800, timeout=120)
    except Exception as e:
        ans = f"AI 回答失败: {e}"
    return {"answer": ans, "action": action}


def _ask_query(action, employee, category=""):
    """按 action 复用现有查询逻辑,返回文本上下文喂总结 LLM。"""
    import detector
    from collections import Counter, defaultdict
    s = Session()
    try:
        if action == "employee_risk" and employee:
            p = s.query(ProfileRow).filter_by(employee_id=employee).first()
            risk_evs = []
            for e in (s.query(EventRow).filter_by(employee_id=employee)
                      .order_by(desc(EventRow.occurred_at)).limit(500).all()):
                dom = (e.raw or {}).get("domain") or ""
                if (e.category == "WEB" and dicts.risk_class(dom)) or \
                   (e.category == "DOC" and e.action in detector.WRITE_ACTIONS):
                    risk_evs.append(e)
                if len(risk_evs) >= 15:
                    break
            vs = s.query(VerdictRow).filter_by(employee_id=employee).order_by(desc(VerdictRow.window_start)).limit(10).all()
            lines = [f"员工 {employee}:",
                     f"画像: {profiles.summarize_for_llm(p.payload) if p else '无画像'}",
                     f"风险行为 {len(risk_evs)} 条:"]
            for e in risk_evs[:10]:
                dom = (e.raw or {}).get("domain") or e.target_value
                lines.append(f"  {e.occurred_at} | {dicts.risk_class(dom) or e.action} | {dom}")
            lines.append(f"研判 {len(vs)} 条: " + "; ".join(f"{v.intent} R{v.risk_score}" for v in vs[:8]))
            return "\n".join(lines)
        if action == "alerts":
            rows = s.query(AlertRow).order_by(desc(AlertRow.risk_score), desc(AlertRow.created_at)).limit(10).all()
            if not rows:
                return "当前无告警。"
            return "告警 top10:\n" + "\n".join(f"{a.employee_id} | {a.scenario} | R{a.risk_score} | {a.summary}" for a in rows)
        if action == "slack":
            et = Counter(); es = Counter()
            for e in s.query(EventRow).filter(EventRow.category == "WEB").yield_per(2000):
                et[e.employee_id] += 1
                cat = dicts.slack_category((e.raw or {}).get("domain") or "")
                if cat and e.occurred_at and 9 <= e.occurred_at.hour < 18:
                    es[e.employee_id] += 1
            top = sorted([(e, es[e], et[e]) for e in es if et[e] > 50], key=lambda x: -x[1])[:10]
            if not top:
                return "无摸鱼数据。"
            return "摸鱼榜 top10(工作时段娱乐占比):\n" + "\n".join(f"{e} 摸鱼{sn}/{tn} ({round(sn/tn*100)}%)" for e, sn, tn in top)
        if action == "who_risk":
            # category(远程控制/网盘/邮箱/招聘/文件助手) → risk_class 标签模糊匹配
            cat_map = {"远程控制": "远程控制", "网盘": "网盘", "邮箱": "个人邮箱", "招聘": "招聘", "文件助手": "微信文件助手"}
            key = next((k for k in cat_map if k in category), None)
            target = cat_map.get(key, category) if key else category
            rcnt = Counter()
            for e in s.query(EventRow).filter(EventRow.category == "WEB").yield_per(2000):
                dom = (e.raw or {}).get("domain") or ""
                rc = dicts.risk_class(dom)
                if rc and target and (target in rc or rc in target):
                    rcnt[e.employee_id] += 1
            if not rcnt:
                return f"近期无人访问{target or '该类'}网站。"
            return f"访问{target}类网站的员工(访问次数):\n" + "\n".join(f"{emp} {n}次" for emp, n in rcnt.most_common(20))
        if action == "attendance":
            today = bj_now().date().isoformat()
            today_active = set(); eh = defaultdict(set)
            for emp_id, occ in s.query(EventRow.employee_id, EventRow.occurred_at).yield_per(2000):
                if occ:
                    try:
                        d = occ.date().isoformat(); h = occ.hour  # occurred_at 是 datetime 对象,用属性非切片
                        eh[emp_id].add((d, h))
                        if d == today:
                            today_active.add(emp_id)
                    except Exception:
                        pass
            all_emps = set(eh.keys())
            not_today = sorted(all_emps - today_active)
            lines = [f"今日({today})有活动 {len(today_active)}人 / 全员 {len(all_emps)}人, 今日无活动 {len(not_today)}人(可能不在岗/未用电脑)。"]
            if not_today:
                lines.append("今日无活动: " + ", ".join(not_today[:20]))
            abnormal = []
            for emp_id in all_emps:
                days = {d for d, h in eh[emp_id]}; hours = sorted({h for d, h in eh[emp_id]})
                if hours and (len(days) <= 1 or hours[0] < 7):
                    mark = "活跃≤1天" if len(days) <= 1 else f"凌晨{hours[0]}点活动"
                    abnormal.append(f"{emp_id}({mark})")
            if abnormal:
                lines.append("异常: " + ", ".join(abnormal[:15]))
            return "\n".join(lines)
        if action == "help":
            return ("系统能力: 安全告警(邮箱/网盘/文件助手/远程控制/招聘)、效率监控(视频/社交/购物/资讯/音乐摸鱼)、画像(风险行为/基线)。\n"
                    "规则: 个人邮箱/网盘公司禁止→访问即违规; 微信文件助手=外发; 远程控制降权; 招聘=求职意图。\n"
                    "可问: 某员工风险行为 / 告警榜 / 摸鱼榜 / 在岗情况 / 谁访问了网盘·邮箱·招聘·文件助手·远程控制。")
        return ""
    finally:
        s.close()


# ---------------- AI 规则建议（建议 + 人工确认）----------------
@app.post("/api/rules/suggest")
def rules_suggest():
    """AI 扫未分类高频域名,建议加到风险/摸鱼词库(只返回建议,不写库)。"""
    import llm_client, json as _json, re as _re
    from collections import Counter
    s = Session()
    try:
        unclass = Counter(); kw_hits = set()
        # 风险/摸鱼关键词: 含这些的未分类域名即使低频也要扫,避免漏掉招聘/网盘/邮箱/视频等
        RISK_KW = ("job", "zhaopin", "recruit", "resume", "hr", "hire", "cv", "mail",
                   "pan", "disk", "cloud", "drive", "upload", "video", "shop", "mall",
                   "weibo", "zhihu", "douban", "game", "novel", "comic")
        for e in s.query(EventRow).filter(EventRow.category == "WEB").yield_per(2000):
            d = (e.raw or {}).get("domain") or ""
            if d and not dicts.risk_class(d) and not dicts.slack_category(d):
                unclass[d] += 1
                if any(k in d.lower() for k in RISK_KW):
                    kw_hits.add(d)
        top = unclass.most_common(30)
        for d in kw_hits:  # 补充含风险关键词的域名(低频但疑似风险/摸鱼),确保被AI扫到
            if d not in dict(top):
                top.append((d, unclass[d]))
        if not top:
            return {"suggestions": [], "msg": "无未分类高频域名"}
        sys_p = ("你是域名分类助手。对每个域名判断归属,只输出 JSON 数组 [{domain, target, cat, reason}]。\n"
                 "target: netdisk_domains(网盘云盘) / personal_email_domains(个人邮箱) / recruitment_sites(招聘求职) / slack_domains(摸鱼娱乐) / ignore(正常办公/厂商后台/CDN/SDK/无关)。\n"
                 "cat: 仅 target=slack_domains 时填 视频/社交/购物/资讯/音乐 之一,否则空字符串。\n"
                 "reason: 一句中文理由。只输出 JSON 数组。")
        user = "域名列表(域名 出现次数):\n" + "\n".join(f"{d} {n}" for d, n in top)
        raw = llm_client.chat([{"role": "system", "content": sys_p}, {"role": "user", "content": user}],
                              max_tokens=1500, timeout=120)
        m = _re.search(r"\[.*\]", raw, _re.S)
        suggestions = []
        if m:
            try:
                suggestions = _json.loads(m.group(0))
            except Exception:
                pass
        hit_map = dict(top)
        for it in suggestions:
            it["hits"] = hit_map.get((it.get("domain") or "").lower(), 0)
        return {"suggestions": suggestions}
    finally:
        s.close()


@app.post("/api/rules/apply")
def rules_apply(body: dict = Body(...)):
    """采纳建议: 把 domain 加到 target_dict(slack_domains 时加到 cat 列表)。"""
    domain = (body.get("domain") or "").lower().strip()
    target = body.get("target_dict") or body.get("target") or ""
    cat = body.get("cat") or ""
    if not domain or target not in dicts.DEFAULTS:
        raise HTTPException(400, "无效 target 或 domain")
    if target == "slack_domains":
        cur = dicts.get("slack_domains")
        if not isinstance(cur, dict):
            cur = {}
        if cat:
            cur[cat] = list(cur.get(cat) or [])
            if domain not in cur[cat]:
                cur[cat].append(domain)
        dicts.set_dict("slack_domains", cur)
    else:
        cur = list(dicts.get(target) or [])
        if domain not in cur:
            cur.append(domain)
        dicts.set_dict(target, cur)
    return {"ok": True, "target": target, "domain": domain, "cat": cat}


# ---------------- 托管前端（放最后，避免拦截 /api）----------------
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
