"""FastAPI 后端：AI 判断/告警/事件/员工/导入/反馈 API + 托管前端静态页。

启动:  python api.py   然后浏览器打开 http://127.0.0.1:8000
"""
import os
import re
import shutil
import tempfile

from fastapi import Body, FastAPI, File, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, func

from db import (AlertRow, EventRow, ExceptionRow, FeedbackRow, ProfileRow, RawLogRow, Session, VerdictRow, bj_now, init_db, json_field)
import pipeline
import profiles
import dicts
import syslog_recv

app = FastAPI(title="IP-Guard 员工行为分析")
init_db()
# 若上次启用了 syslog，自动恢复监听
_se = dicts.get_setting("syslog_enabled", "0")
print("[startup] syslog_enabled =", _se)
if _se == "1":
    try:
        syslog_recv.start(dicts.get_setting("syslog_host", "0.0.0.0"),
                          int(dicts.get_setting("syslog_port", "8514")))
        print("[startup] syslog 自启成功, enabled =", syslog_recv.status().get("enabled"))
    except Exception as e:
        print("[startup] syslog 自启失败:", e)
    syslog_recv.start_watchdog()  # 兜底: syslog停了自动重启(每60s检查)

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


# ---------------- 工具 ----------------

# 员工枚举降噪：events.employee_id 里混着设备/网关标识(IP/MAC 地址，如 10.4.245.1)，
# 不是真人。统计"全员/上线/在岗"时必须排除，否则分母被设备撑大，还会把网关列成
# "今日无活动的人"。按 IP/MAC 形状判定为非人(纯事实降噪，留代码、不交给AI判断)。
_NON_PERSON = re.compile(
    r'^(?:'
    r'\d{1,3}(?:\.\d{1,3}){3}'                   # IPv4(设备/网关，如 10.4.245.1)
    r'|[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}'     # MAC(冒号)
    r'|[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}'     # MAC(连字符)
    r')$')

def _is_person(emp_id) -> bool:
    """employee_id 是否代表真人(排除 IP/MAC 等设备标识)。"""
    return bool(emp_id) and not _NON_PERSON.match((emp_id or "").strip())


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
    # 批量查事件(原逐 hash 单查=N+1,列表页100 verdicts × 10 hash = 1000 次查询)。一次 in_ 批查。
    hashes = r.event_hashes or []
    events = []
    if hashes:
        ev_map = {e.event_hash: e for e in
                  s.query(EventRow).filter(EventRow.event_hash.in_(hashes[:50])).all()}
        events = [_event_dict(ev_map[h]) for h in hashes if h in ev_map]
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
def list_alerts(severity: str | None = None, limit: int = 200, when: str | None = None, status: str | None = None):
    """告警列表。when(today/yesterday/week) 与 status(NEW/handled) 在 SQL 层过滤，
    避免按 risk 排序 + limit 时把今日/未处理告警截断（大屏人数与条数曾因此不一致）。"""
    from datetime import timedelta
    s = Session()
    try:
        q = s.query(AlertRow).order_by(desc(AlertRow.risk_score), desc(AlertRow.created_at))
        if severity:
            q = q.filter(AlertRow.severity == severity)
        if status == "NEW":
            q = q.filter(AlertRow.status == "NEW")
        elif status == "handled":          # CONFIRMED / FP / CLOSED 等一切非 NEW
            q = q.filter(AlertRow.status != "NEW")
        if when in ("today", "yesterday", "week"):
            _n = bj_now()
            _today = _n - timedelta(hours=_n.hour, minutes=_n.minute, seconds=_n.second, microseconds=_n.microsecond)
            if when == "today":
                q = q.filter(AlertRow.window_start >= _today)
            elif when == "yesterday":
                q = q.filter(AlertRow.window_start >= _today - timedelta(days=1),
                             AlertRow.window_start < _today)
            else:                           # week 近7天
                q = q.filter(AlertRow.window_start >= _today - timedelta(days=7))
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
        # 风险行为:扫近期 WEB/DOC 事件筛 risk_class。
        # 用 event_hashes 反查更准——先从该员工的 verdicts(已研判过的可疑窗口)取
        # event_hashes,反查出真正被判定为风险的事件;不足再扫最近事件补齐。避免全表扫描,
        # 也避免 limit(300) 漏掉较早的风险访问(招聘/外发可能在几天前)。
        risk_evs = []
        v_hashes = set()
        for vr in s.query(VerdictRow).filter_by(employee_id=emp).order_by(desc(VerdictRow.window_start)).limit(60).all():
            v_hashes.update(vr.event_hashes or [])
        if v_hashes:  # 优先:研判命中的事件(就是 AI 判过的风险行为,最相关)
            for e in s.query(EventRow).filter(EventRow.event_hash.in_(list(v_hashes)[:400])).all():
                dom = (e.raw or {}).get("domain") or ""
                if (e.category == "WEB" and dicts.risk_class(dom)) or \
                   (e.category == "DOC" and e.action in detector.WRITE_ACTIONS):
                    risk_evs.append(e)
                if len(risk_evs) >= 30:
                    break
        for e in (s.query(EventRow).filter_by(employee_id=emp)  # 补齐:近期事件再扫一轮
                  .order_by(desc(EventRow.occurred_at)).limit(300).all()):
            if len(risk_evs) >= 30:
                break
            dom = (e.raw or {}).get("domain") or ""
            if (e.category == "WEB" and dicts.risk_class(dom)) or \
               (e.category == "DOC" and e.action in detector.WRITE_ACTIONS):
                ev_hash = e.event_hash
                if not any(x.event_hash == ev_hash for x in risk_evs):
                    risk_evs.append(e)
        # 摸鱼会话: 连续娱乐事件(60min内)聚合成一段,算时长(什么时候看/看什么/看多久)
        _se = []
        for e in (s.query(EventRow).filter_by(employee_id=emp).filter(EventRow.category == "WEB")
                  .order_by(desc(EventRow.occurred_at)).limit(500).all()):
            dom = (e.raw or {}).get("domain") or ""
            sc = dicts.slack_category(dom)
            if sc and e.occurred_at:
                _se.append((e.occurred_at, dom, sc))
        _se.sort(key=lambda x: x[0])
        sessions, cur = [], None
        for occ, dom, sc in _se:
            if cur and (occ - cur["end"]).total_seconds() <= 3600:
                cur["end"] = occ; cur["domains"][dom] = cur["domains"].get(dom, 0) + 1; cur["count"] += 1
            else:
                if cur:
                    sessions.append(cur)
                cur = {"start": occ, "end": occ, "domains": {dom: 1}, "cat": sc, "count": 1}
        if cur:
            sessions.append(cur)
        for ss in sessions:
            ss["duration"] = int((ss["end"] - ss["start"]).total_seconds() / 60)
            ss["domains"] = sorted(ss["domains"].keys())
        sessions.sort(key=lambda x: -x["duration"])
        vs = (s.query(VerdictRow).filter_by(employee_id=emp)
              .order_by(desc(VerdictRow.window_start)).limit(20).all())
        # 全量分类/来源统计(供画像事件分类/数据来源卡,不用50条样本)
        cat_counts = {c: n for c, n in s.query(EventRow.category, func.count(EventRow.id))
                      .filter(EventRow.employee_id == emp).group_by(EventRow.category).all()}
        src_counts = {src: n for src, n in s.query(EventRow.source, func.count(EventRow.id))
                      .filter(EventRow.employee_id == emp).group_by(EventRow.source).all()}
        # 全量研判统计(不受 vs limit 20 影响,供画像研判次数/最高风险)
        vd_total = s.query(func.count(VerdictRow.id)).filter(VerdictRow.employee_id == emp).scalar() or 0
        vd_max = s.query(func.max(VerdictRow.risk_score)).filter(VerdictRow.employee_id == emp).scalar()
        # 该员工的告警明细(与用户视图'告警N条'同源,供画像对齐展示)
        emp_alerts = s.query(AlertRow).filter(AlertRow.employee_id == emp).order_by(desc(AlertRow.risk_score)).all()
        return {
            "employee": emp,
            "category_counts": cat_counts,
            "source_counts": src_counts,
            "verdict_count": vd_total,
            "max_risk": vd_max,
            "alert_count": len(emp_alerts),
            "alerts": [{"scenario": a.scenario, "severity": a.severity, "risk_score": a.risk_score,
                        "status": a.status, "summary": a.summary,
                        "window_start": a.window_start.isoformat() if a.window_start else None} for a in emp_alerts],
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
            "slack_sessions": [{
                "start": ss["start"].isoformat() if ss["start"] else None,
                "end": ss["end"].isoformat() if ss["end"] else None,
                "duration": ss["duration"], "cat": ss["cat"],
                "domains": ss["domains"][:3], "count": ss["count"],
            } for ss in sessions[:20]],
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
        _today = bj_now().replace(hour=0, minute=0, second=0, microsecond=0)
        et = {r[0]: r[1] for r in
              s.query(EventRow.employee_id, func.count(EventRow.id))
              .filter(EventRow.occurred_at >= _today).group_by(EventRow.employee_id).all()}
        out = [{"computer": e, "event_count": c, "event_count_today": et.get(e, 0),
                "last_seen": (t.isoformat() if t else None),
                "max_risk": vr.get(e), "alert_count": al.get(e, 0)} for e, c, t in ev]
        out.sort(key=lambda x: -(x["max_risk"] or 0))
        return out
    finally:
        s.close()


@app.post("/api/ingest")
def ingest(file: UploadFile = File(...)):
    """上传 xlsx/csv → 批量导入 → 建画像 → 异步启动研判（立即返回，前端轮询进度）。
    用 def(非 async)：内部 shutil/ingest_file/build_profiles 都是同步阻塞 IO，async 会
    阻塞事件循环卡住其它请求；FastAPI 把 def 端点丢线程池跑，不阻塞主循环。"""
    suffix = os.path.splitext(file.filename or "")[1] or ".xlsx"
    fd, tmp = tempfile.mkstemp(suffix=suffix)  # 唯一名,避免并发上传互相覆盖
    os.close(fd)
    try:
        with open(tmp, "wb") as f:
            shutil.copyfileobj(file.file, f)
        n = pipeline.ingest_file(tmp)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
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
        # 先校验告警存在再写 FeedbackRow，避免写出指向不存在 alert_id 的孤儿反馈
        a = s.get(AlertRow, alert_id)
        if not a:
            raise HTTPException(404, f"告警 {alert_id} 不存在")
        s.add(FeedbackRow(alert_id=alert_id, label=label, reason=reason))
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

        # 研判量（今日/昨日/总量）—— "今日"按 window_start（行为时间）计，
        # 与告警同源、与研判页 isToday 过滤一致，避免 created_at（判定写入时间）跨天漂移。
        vd_today = s.query(VerdictRow).filter(VerdictRow.window_start >= today_start).count()
        vd_yesterday = s.query(VerdictRow).filter(
            VerdictRow.window_start >= yesterday_start,
            VerdictRow.window_start < today_start
        ).count()
        vd_total = s.query(VerdictRow).count()
        vd_ai = s.query(VerdictRow).filter(VerdictRow.ai_participated == 1).count()
        vd_fallback = s.query(VerdictRow).filter(VerdictRow.ai_participated == 0).count()

        # 告警（今日/昨日/总量）
        al_today = s.query(AlertRow).filter(AlertRow.window_start >= today_start).count()
        al_yesterday = s.query(AlertRow).filter(
            AlertRow.window_start >= yesterday_start,
            AlertRow.window_start < today_start
        ).count()
        al_total = s.query(AlertRow).count()
        st_rows = s.query(AlertRow.status, _f.count(AlertRow.id)).group_by(AlertRow.status).all()
        alert_status = {r[0]: r[1] for r in st_rows}
        # 今日告警涉及人数（distinct employee，window_start 今日）—— 与条数同源，
        # 供大屏"涉及 N 人"。不再由前端从有限(risk 排序 limit)列表推算，避免被截断。
        al_today_people = s.query(_f.count(_f.distinct(AlertRow.employee_id))).filter(
            AlertRow.window_start >= today_start).scalar() or 0
        # 今日严重告警(76+)条数——供大屏"今日严重告警"N 值。SQL 层计数，避免前端从
        # risk 排序 limit 的样本推算、超过样本量时漏算。
        al_today_critical = s.query(AlertRow).filter(
            AlertRow.window_start >= today_start, AlertRow.risk_score >= 76).count()
        # 告警按场景分布(全量 group_by，无 risk 排序截断)——供大屏饼图，避免前端用
        # risk 排序 limit 样本导致高风险场景被系统性放大。
        al_by_scenario = {r[0] or "未识别": r[1] for r in
            s.query(AlertRow.scenario, _f.count(AlertRow.id)).group_by(AlertRow.scenario).all()}

        # 豁免(expires_at 按 naive UTC 写入,这里同源比较;用 timezone-aware 再剥离 tz,
        # 避免 utcnow() 在 Py3.12 的 DeprecationWarning 刷日志)
        _utc_now = datetime.now(timezone.utc).replace(tzinfo=None)
        ex_count = s.query(ExceptionRow).filter(
            (ExceptionRow.expires_at.is_(None)) | (ExceptionRow.expires_at > _utc_now)
        ).count()
        # 事件保留期(天)——供前端"系统健康"卡展示真实配置，而非写死 90
        retention_days = int(dicts.get_setting("retention_days", "90"))

        # 数据库大小
        import os as _os
        db_path = _os.path.join(_os.path.dirname(__file__), "data", "ipguard.db")
        db_size = _os.path.getsize(db_path) if _os.path.exists(db_path) else 0

        # 去重/降噪统计（总事件中WEB事件比例，估算降噪效果）
        web_total = s.query(EventRow).filter(EventRow.category == "WEB").count()

        # 画像上次全量重建时间（as_of 存的是 utcnow naive UTC，转 epoch 供前端算"X分钟前"）
        _lp = s.query(_f.max(ProfileRow.as_of)).scalar()
        profile_updated_ts = int(_lp.replace(tzinfo=timezone.utc).timestamp()) if _lp else None

        # 告警日趋势(近7天 [date, count])
        _day = {}
        for _i in range(6, -1, -1):
            _dk = (bj_now() - timedelta(days=_i)).date().isoformat()
            _day[_dk] = 0
        # 过滤下界与上方 _day 的 key 对齐：key 是"今天自然日往前 6 天"，
        # 下界也用 today_start-6d（最老一天 00:00），否则最老一柱只有[此刻,23:59]的数据，系统性偏低。
        for _r in s.query(AlertRow).filter(AlertRow.window_start >= today_start - timedelta(days=6)).all():
            if _r.window_start:
                _k = _r.window_start.date().isoformat()
                if _k in _day:
                    _day[_k] += 1
        alerts_by_day = list(_day.items())

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
                "today": al_today, "yesterday": al_yesterday, "total": al_total,
                "today_people": al_today_people, "today_critical": al_today_critical,
                "by_scenario": al_by_scenario, "status": alert_status,
                "list": [{
                    "employee": r.employee_id, "scenario": r.scenario,
                    "risk_score": r.risk_score, "status": r.status, "summary": r.summary,
                } for r in s.query(AlertRow).order_by(desc(AlertRow.risk_score), desc(AlertRow.created_at)).limit(50).all()],
            },
            "exceptions": ex_count,
            "db_size_mb": round(db_size / 1024 / 1024, 1),
            "employees": s.query(EventRow.employee_id).filter(EventRow.occurred_at >= today_start).distinct().count(),
            "employees_total": s.query(EventRow.employee_id).distinct().count(),
            "retention_days": retention_days,
            "detect": pipeline.detection_status(),
            "syslog": syslog_recv.status(),
            "profile_updated_ts": profile_updated_ts,
            "alerts_by_day": alerts_by_day,
        }
    finally:
        s.close()


_eff_cache = {"data": None, "ts": 0}
_eff_summary_cache = {"data": None, "ts": 0}

@app.get("/api/efficiency")
def efficiency():
    """工作效率统计: 每员工工作时段(9-12,14-18 排除午休)访问构成(摸鱼/工作)+在岗天数/时段。"""
    import time
    if _eff_cache["data"] is not None and time.time() - _eff_cache["ts"] < 60:
        return _eff_cache["data"]
    from collections import Counter
    from datetime import timedelta
    s = Session()
    try:
        # 只扫近 7 天(效率分析看近期,不必全量历史)。原全量 98 万行→约 30 万行,
        # 冷启动从 30s 降到数秒。性能:SQL 直接抽 domain(免 ORM 水合逐行 JSON 解析),
        # 域名分类按 distinct 域名缓存(数千个)。
        since = bj_now() - timedelta(days=7)
        dom_expr = json_field(EventRow.raw, 'domain')
        rows = s.query(EventRow.employee_id, EventRow.occurred_at, EventRow.count, dom_expr).filter(
            EventRow.category == "WEB", EventRow.occurred_at >= since).all()
        emp = {}
        dom_cache = {}
        for emp_id, occ, cnt, dom in rows:
            r = emp.setdefault(emp_id, {"wh": 0, "slack": 0, "work": 0, "cats": Counter(),
                                        "days": set(), "hours": set(), "stimes": []})
            if occ:
                r["days"].add(occ.date()); r["hours"].add(occ.hour)
            d = dom or ""
            if d not in dom_cache:
                cat = dicts.slack_category(d)
                dom_cache[d] = (cat, (not cat and not dicts.risk_class(d) and bool(dicts.work_category(d))))
            cat, is_work = dom_cache[d]
            # 只统计工作时段(9-12,14-18,排除午休)的访问构成;非工时事件仅计入在岗天数/时段
            if occ and (9 <= occ.hour < 12 or 14 <= occ.hour < 18):
                c = cnt or 1
                r["wh"] += c
                if cat:
                    r["slack"] += c; r["cats"][cat] += c; r["stimes"].append(occ)
                elif is_work:
                    r["work"] += c
        out = []
        for k, r in emp.items():
            hours = sorted(r["hours"])
            st = sorted(r["stimes"])
            # 摸鱼时长估算:日志只有访问时刻无停留时长,用'段累计'近似——
            # 同一天内 ≤30min gap 的娱乐访问连成一段,每段时长=首末跨度(碎片化摸鱼聚合)。
            # 各段相加=总摸鱼时长,÷活跃天数=日均。比旧'最长跨度'更准(旧算法把跨天断续当连续)。
            from collections import defaultdict as _dd
            by_day = _dd(list)
            for t in st:
                by_day[t.date()].append(t)
            total_min = 0.0
            mx = 0.0  # 保留 max_span(单日最长一段),用30min gap 更严
            for d, ts in by_day.items():
                ts.sort(); seg_s = seg_e = None; day_min = 0.0
                for t in ts:
                    if seg_e is not None and (t - seg_e).total_seconds() <= 1800:  # 30min gap
                        seg_e = t
                    else:
                        if seg_e is not None:
                            day_min += (seg_e - seg_s).total_seconds()
                        seg_s = seg_e = t
                if seg_e is not None:
                    day_min += (seg_e - seg_s).total_seconds()
                total_min += day_min
                mx = max(mx, day_min)
            active_days = len(r["days"]) or 1
            slack_avg = round(total_min / 60 / active_days)  # 日均摸鱼分钟
            wh = r["wh"]
            classified = r["slack"] + r["work"]
            out.append({"employee": k, "total": wh, "slack": r["slack"],
                        "pct": round(r["slack"] / classified * 100, 1) if classified else 0,
                        "cats": dict(r["cats"]), "active_days": len(r["days"]),
                        "hour_min": hours[0] if hours else None, "hour_max": hours[-1] if hours else None,
                        "slack_avg": slack_avg, "max_span": round(mx / 60), "work": r["work"],
                        "work_pct": round(r["work"] / classified * 100, 1) if classified else 0,
                        "classified": classified})
        out.sort(key=lambda x: -(x.get("slack_avg") or 0))
        _eff_cache["data"] = out; _eff_cache["ts"] = time.time()
        return out
    finally:
        s.close()


@app.get("/api/efficiency/summary")
def efficiency_summary():
    """近7天工作时段摸鱼 → AI 按人总结(谁什么时候干了什么影响效率)。结果缓存10分钟。"""
    import time as _time, json as _json, re as _re
    import llm_client
    if _eff_summary_cache["data"] is not None and _time.time() - _eff_summary_cache["ts"] < 600:
        return {"items": _eff_summary_cache["data"], "cached": True}
    from collections import defaultdict, Counter
    from datetime import timedelta
    s = Session()
    try:
        since = bj_now() - timedelta(days=7)
        dom_expr = json_field(EventRow.raw, 'domain')
        rows = s.query(EventRow.employee_id, EventRow.occurred_at, EventRow.count, dom_expr).filter(
            EventRow.category == "WEB", EventRow.occurred_at >= since).all()
        emp_slack = defaultdict(list)
        for emp_id, occ, cnt, dom in rows:
            if not occ or (emp_id or "").isdigit():  # 跳过无时间 + 访客(纯数字ID)
                continue
            cat = dicts.slack_category(dom or "")
            if cat and (9 <= occ.hour < 12 or 14 <= occ.hour < 18):
                emp_slack[emp_id].append((occ, cat, cnt or 1))
        # 预筛(≥3次)控成本;按天×类别压缩成文本喂 AI
        lines = []
        for emp, evs in emp_slack.items():
            if len(evs) < 3:
                continue
            by_day = defaultdict(Counter)
            for occ, cat, cnt in evs:
                by_day[occ.strftime("%m-%d")][cat] += cnt
            parts = ["%s %s" % (d, "、".join("%s%d次" % (c, n) for c, n in cats.most_common()))
                     for d, cats in sorted(by_day.items())]
            lines.append("%s: %s" % (emp, "; ".join(parts)))
        if not lines:
            return {"items": [], "msg": "近7天工作时段无明显摸鱼行为"}
        ctx = "\n".join(lines[:60])
        prompt = ("你是企业员工效率分析助手。基于下面员工近7天【工作时段(9-12,14-18)】的摸鱼(娱乐访问)数据,"
                  "挑出真正影响工作效率的行为,按人用一句话总结:谁、什么时段、干了什么(网站类别)、大概多久或几次。"
                  "只挑值得说的(重度/反复),忽略零星1-2次。不编造数据外的内容。"
                  "只输出 JSON 数组 [{\"employee\",\"summary\"}],summary 是一句中文。\n\n数据:\n" + ctx)
        try:
            raw = llm_client.chat([{"role": "system", "content": prompt}, {"role": "user", "content": "请输出 JSON。"}],
                                  max_tokens=2000, timeout=120)
        except Exception as e:
            return {"items": [], "msg": "AI 总结失败: %s" % e}
        m = _re.search(r"\[.*\]", raw, _re.S)
        items = []
        if m:
            try:
                items = _json.loads(m.group(0))
            except Exception:
                items = []
        items = [{"employee": str(it.get("employee", "")).strip(), "summary": str(it.get("summary", "")).strip()}
                 for it in items if it.get("employee") and it.get("summary")]
        _eff_summary_cache["data"] = items; _eff_summary_cache["ts"] = _time.time()
        return {"items": items}
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
            # 原写法 `if r[0]` 把 app 为空的事件整组丢弃，使 "未识别" 分支永远走不到——
            # 意图(给空 app 归"未识别")与实现矛盾。去掉过滤，让空 app 正确归入"未识别"。
            return {(r[0] or "未识别"): r[1] for r in rows}

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
                 "【关键优先级】问题里提到具体员工姓名(如'王帆''朱亮')→ 一律 employee_risk + employee=该姓名,无论问的是招聘/网盘/外发/摸鱼(查这个人的具体行为)。\n"
                 "只有问'谁/哪些人/有没有人'(无具体姓名)访问某类网站 → 才用 who_risk + category。\n"
                 "employee: 仅 employee_risk 时填员工姓名(从问题提取)。\n"
                 "category: 仅 who_risk 时填, 取值 远程控制/网盘/邮箱/招聘/文件助手 之一。\n"
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
    # 兜底: 路由成 who_risk 但问题里其实含具体员工名 → 转 employee_risk(查这个人具体行为)。
    # 避免"王帆访问了哪些招聘网站"被误判成 who_risk(只统计人数,不列具体网站)。
    if action == "who_risk":
        _s2 = Session()
        try:
            _emps = [r[0] for r in _s2.query(EventRow.employee_id).distinct().limit(5000).all()]
        finally:
            _s2.close()
        _hit = next((e for e in _emps if e and e in question), None)
        if _hit:
            action = "employee_risk"; employee = _hit
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
            vs_total = s.query(VerdictRow).filter_by(employee_id=employee).count()
            vs = s.query(VerdictRow).filter_by(employee_id=employee).order_by(desc(VerdictRow.window_start)).limit(12).all()
            # 优先用 verdicts 的 explanation 喂 AI——研判时 AI 已经在 explanation 里写明了
            # 具体域名+次数+意图(如"访问猎聘网 bdfe.liepin.com 1次"),这比扫事件更准更快。
            # 旧版扫该员工【全部】事件做 risk_class,事件多的员工会拖到几十秒超时,导致 AI 答不出。
            lines = [f"员工 {employee}:",
                     f"画像: {profiles.summarize_for_llm(p.payload) if p else '无画像'}",
                     f"研判记录 {vs_total} 条(这是该员工被AI判定过的风险行为,最近 {min(vs_total,12)} 条):"]
            for v in vs:
                lines.append(f"  {v.window_start} | {v.intent} | 风险{v.risk_score} | {v.explanation}")
            # 补充:从这些研判反查具体事件域名(若 AI 问"具体哪些网站",域名比 explanation 更结构化)
            v_hashes = []
            for v in vs:
                v_hashes.extend(v.event_hashes or [])
            if v_hashes:
                dom_cnt = Counter()
                for e in s.query(EventRow).filter(EventRow.event_hash.in_(v_hashes[:400])).all():
                    d = ((e.raw or {}).get("domain") or "").lower()
                    rc = dicts.risk_class(d)
                    if rc and d:
                        dom_cnt[f"{rc}:{d}"] += 1
                if dom_cnt:
                    lines.append("风险域名明细(类别:域名 出现次数): " + ", ".join(f"{k}×{v}" for k, v in dom_cnt.most_common(15)))
            return "\n".join(lines)
        if action == "alerts":
            rows = s.query(AlertRow).order_by(desc(AlertRow.risk_score), desc(AlertRow.created_at)).limit(10).all()
            if not rows:
                return "当前无告警。"
            _today = bj_now().replace(hour=0, minute=0, second=0, microsecond=0)
            # 条数单独 count（原用 len(limit15 列表) 当总数，>15 条时喂给 AI 的数是错的）
            _td_count = s.query(AlertRow).filter(AlertRow.window_start >= _today).count()
            _td = s.query(AlertRow).filter(AlertRow.window_start >= _today).order_by(desc(AlertRow.risk_score)).limit(15).all()
            lines = ["告警 top10(全时段,按风险):"] + [f"  {a.employee_id} | {a.scenario} | R{a.risk_score}" for a in rows]
            lines += ["", f"今日告警 {_td_count} 条(按行为时间):"] + [f"  {a.employee_id} | {a.scenario} | R{a.risk_score} | {a.summary}" for a in _td] if _td else ["", f"今日告警: {_td_count} 条"]
            return "\n".join(lines)
        if action == "slack":
            # 优化:SQL 取 (employee, occurred_at, domain),Python 对 distinct 域名缓存 slack_category。
            et = Counter(); es = Counter()
            dom_expr = json_field(EventRow.raw, 'domain')
            rows = s.query(EventRow.employee_id, EventRow.occurred_at, dom_expr).filter(EventRow.category == "WEB").all()
            dom_cache = {}
            for emp_id, occ, dom in rows:
                et[emp_id] += 1
                d = (dom or "").lower()
                cat = dom_cache.get(d) if d else None
                if d and cat is None:
                    cat = dicts.slack_category(d) or ""
                    dom_cache[d] = cat
                if cat and occ and (9 <= occ.hour < 12 or 14 <= occ.hour < 18):  # 工作时间,排除午休12-14
                    es[emp_id] += 1
            top = sorted([(e, es[e], et[e]) for e in es if et[e] > 50], key=lambda x: -x[1])[:10]
            if not top:
                return "无摸鱼数据。"
            return "摸鱼榜 top10(工作时段娱乐占比):\n" + "\n".join(f"{e} 摸鱼{sn}/{tn} ({round(sn/tn*100)}%)" for e, sn, tn in top)
        if action == "who_risk":
            # category(远程控制/网盘/邮箱/招聘/文件助手) → risk_class 标签模糊匹配
            cat_map = {"远程控制": "远程控制", "网盘": "网盘", "邮箱": "个人邮箱", "招聘": "招聘", "文件助手": "微信文件助手"}
            key = next((k for k in cat_map if k in category), None)
            target = cat_map.get(key, category) if key else category
            # 优化:SQL 只取 (employee,domain),Python 先对 distinct 域名算 risk_class(几千个),
            # 再聚合——避免对 98 万行逐行调 risk_class 导致超时。
            rcnt = Counter()
            dom_expr = json_field(EventRow.raw, 'domain')
            rows = s.query(EventRow.employee_id, dom_expr).filter(EventRow.category == 'WEB').all()
            dom_cache = {}
            for emp_id, dom in rows:
                d = (dom or "").lower()
                if not d:
                    continue
                rc = dom_cache.get(d)
                if rc is None:
                    rc = dicts.risk_class(d) or ""
                    dom_cache[d] = rc
                if rc and target and (target in rc or rc in target):
                    rcnt[emp_id] += 1
            if not rcnt:
                return f"近期无人访问{target or '该类'}网站。"
            return f"访问{target}类网站的员工(访问次数):\n" + "\n".join(f"{emp} {n}次" for emp, n in rcnt.most_common(20))
        if action == "attendance":
            # 优化:SQL 取 distinct (employee, date(occurred_at), hour) 聚合,避免逐行遍历98万事件。
            today = bj_now().date().isoformat()
            today_active = set(); eh = defaultdict(set)
            rows = s.query(EventRow.employee_id, EventRow.occurred_at).filter(EventRow.occurred_at.isnot(None)).all()
            for emp_id, occ in rows:
                if not _is_person(emp_id):  # 排除 IP/MAC 等设备标识，否则被当成"未上线的人"拉低上线比例
                    continue
                try:
                    d = occ.date().isoformat(); h = occ.hour
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
        # 优化:SQL 先按域名 group by + count(98万行→几千唯一域名),Python 只对
        # distinct 域名调一次分类函数。旧版逐行调3个分类函数,98万×3次字典遍历,极慢。
        unclass = Counter(); kw_hits = set()
        # 含这些关键词的未分类域名即使低频也要扫,避免漏掉新风险/新应用
        RISK_KW = ("job", "zhaopin", "recruit", "resume", "hr", "hire", "cv", "mail",
                   "pan", "disk", "cloud", "drive", "upload", "video", "shop", "mall",
                   "weibo", "zhihu", "douban", "game", "novel", "comic",
                   # 新增:覆盖新风险线索
                   "send", "transfer", "share", "sync", "backup", "export",  # 外发/同步
                   "chat", "ai", "gpt", "llm", "prompt",  # AI助手
                   "wiki", "notion", "confluence", "figma",  # 协作/设计平台(数据外发)
                   "pastebin", "github", "gist", "codepen",  # 代码粘贴/外发
                   "tunnel", "ngrok", "frp", "proxy",  # 内网穿透/代理
                   "telegram", "whatsapp", "signal",  # 即时通讯(外发)
                   "weibo", "zhihu", "douban", "game", "novel", "comic")
        dom_expr = json_field(EventRow.raw, 'domain')
        # SQLite: 直接 group by json 提取的 domain 字段
        from sqlalchemy import func as _f
        rows = s.query(dom_expr, _f.count(EventRow.id)).filter(
            EventRow.category == "WEB", dom_expr.isnot(None)
        ).group_by(dom_expr).all()
        cls_cache = {}
        for d, n in rows:
            d = (d or "").strip()
            if not d:
                continue
            cls = cls_cache.get(d)
            if cls is None:
                cls = "risk" if dicts.risk_class(d) else ("slack" if dicts.slack_category(d) else ("work" if dicts.work_category(d) else "unclass"))
                cls_cache[d] = cls
            if cls == "unclass":
                unclass[d] += n
                if any(k in d.lower() for k in RISK_KW):
                    kw_hits.add(d)
        top = unclass.most_common(60)
        for d in kw_hits:  # 补充含风险关键词的域名(低频但疑似风险/摸鱼),确保被AI扫到
            if d not in dict(top):
                top.append((d, unclass[d]))
        # 预过滤明显的云服务/CDN/SDK 噪音子域(微软云/CDN/统计/证书等长串子域),
        # 这些喂给AI无价值且占名额。保留短域名(更像真实站点)。
        NOISE_HINT = ("office.net", "office.com", "sharepoint", "microsoft", "cdn", "akamai",
                      "cloudfront", "ic3-edf", "trouter", "svc.ms", "1cdn", "office365",
                      "skype", "trouter", "aria.microsoft", "events.data", "telemetry",
                      "in.applicationinsights", "blob.core", "trouser")
        top = [(d, n) for d, n in top if len(d) < 48 and not any(x in d.lower() for x in NOISE_HINT)][:30]
        if not top:
            return {"suggestions": [], "msg": "无未分类高频域名"}
        sys_p = ("你是企业数据安全助手。分析这些【未分类】的域名,判断是否需要纳入风险监控。\n"
                 "对每个域名输出 JSON: {domain, target, cat, reason}\n"
                 "target 取值:\n"
                 "- 已知风险类(纳入对应字典): netdisk_domains(网盘云盘) / personal_email_domains(个人邮箱) / recruitment_sites(招聘求职) / remote_control_domains(远程控制) / vpn_domains(翻墙) / code_repo_domains(代码仓库) / wechat_file_domains(微信文件助手) / ai_assistant_domains(AI助手chatgpt/deepseek等,往AI塞数据) / slack_domains(摸鱼娱乐)\n"
                 "- **suspect_new(疑似新风险)**: 不属于上述任何类,但像数据外发/泄露/规避监控的可疑行为(如未知网盘、匿名传输、临时邮箱、屏幕共享、代码粘贴pastebin、内网穿透ngrok/frp、加密货币、敏感数据爬取等)。这类即使无法精确归类也要标出,供人工审核。\n"
                 "- ignore: 明确的正常办公/厂商后台/CDN/SDK/系统更新/认证服务\n"
                 "cat: 仅 target=slack_domains 时填 视频/社交/购物/资讯/音乐 之一,否则空字符串。\n"
                 "reason: 一句中文,说明判断依据。\n"
                 "原则:宁可多标 suspect_new 让人工复核,也不要漏掉可疑域名。只输出 JSON 数组。")
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


# ---------------- 原始日志查看 ----------------
@app.get("/api/raw_logs")
def raw_logs(start: str | None = None, end: str | None = None, log_type: str | None = None,
             user: str | None = None, kw: str | None = None, limit: int = 500):
    """原始 syslog 报文查询(按时间/log_type/user/关键词筛选),返回total+items。"""
    s = Session()
    try:
        q = s.query(RawLogRow)
        if start:
            q = q.filter(RawLogRow.received_at >= start)
        if end:
            q = q.filter(RawLogRow.received_at <= end)
        if log_type:
            q = q.filter(RawLogRow.log_type == log_type)
        if user:
            q = q.filter(RawLogRow.user.contains(user))
        if kw:
            q = q.filter(RawLogRow.msg.contains(kw))
        total = q.count()
        rows = q.order_by(desc(RawLogRow.received_at)).limit(min(limit, 5000)).all()
        return {"total": total, "items": [{"id": r.id, "received_at": r.received_at.isoformat() if r.received_at else None,
                 "log_type": r.log_type, "user": r.user, "app": r.app, "msg": r.msg} for r in rows]}
    finally:
        s.close()


# ---------------- 托管前端（放最后，避免拦截 /api）----------------
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
