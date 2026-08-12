"""流水线编排：批量导入 → 建画像 → 增量研判（3 阶段，研判时不持写锁）→ 单飞异步。"""
from __future__ import annotations

import concurrent.futures
from datetime import datetime, timedelta
import re
import sys
import threading

from db import (AlertRow, EventRow, ExceptionRow, Session, SettingRow, VerdictRow,
                bj_now, init_db, severity_of)
from models import CanonicalEvent
from parser_ipguard import parse_ipguard_excel
from parser_sangfor import parse_sangfor
from web_aggregator import aggregate
import dicts
import detector
import profiles

INTENT_MAP = {"job_seeking": "求职离职", "data_exfiltration": "数据外发",
              "baseline_deviation": "行为偏离", "policy_violation": "违规", "normal_work": "正常"}


def _ignored_employees() -> set:
    """需要忽略的员工名集合(测试账号等):逗号/换行分隔的 setting。
    与访客(纯数字)过滤并用,避免开发期测试号污染生产统计与告警。"""
    raw = dicts.get_setting("ignored_employees", "") or ""
    return {x.strip() for x in re.split(r"[,\n，]", raw) if x.strip()}


def _window_trigger_domains(w) -> set:
    """提取窗口里触发的 high/job 级风险域名(用于研判去重 key)。
    只取真正会触发 should_trigger 的高危域名,普通域名不算(否则去重过宽)。"""
    doms = set()
    for e in w:
        if e.category == "WEB":
            d = (e.raw or {}).get("domain") or e.target_value
            if d and dicts.risk_tier(d) in ("high", "job"):
                doms.add(d.lower())
    return doms


def _recently_judged(rs, emp: str, domains: set, hours: int) -> bool:
    """该员工对这些高危域名中的任一域名,在最近 hours 小时内是否已研判过。
    用于抑制"VPN 后台持续连接"这类同域名反复研判(朱亮 228 次问题的根因)。
    event_hashes 命中即可——研判过的窗口其 event_hashes 已落库,反查这些 hash 是否属当前域名。"""
    if not domains or hours <= 0:
        return False
    cutoff = bj_now() - timedelta(hours=hours)
    # 该员工最近 hours 小时的研判,取 event_hashes
    rows = rs.query(VerdictRow).filter(
        VerdictRow.employee_id == emp, VerdictRow.window_start >= cutoff
    ).all()
    if not rows:
        return False
    # 反查这些研判的 event_hashes 对应的事件域名,看是否与当前窗口的域名重叠
    hashes = set()
    for r in rows:
        hashes.update(r.event_hashes or [])
    if not hashes:
        return False
    evs = rs.query(EventRow).filter(EventRow.event_hash.in_(list(hashes)[:400]),
                                    EventRow.category == "WEB").all()
    judged_doms = {(e.raw or {}).get("domain", "").lower() for e in evs}
    judged_doms.discard("")
    return bool(domains & judged_doms)


def _alert_count() -> int:
    s = Session()
    try:
        return s.query(AlertRow).count()
    finally:
        s.close()


def ingest_file(path: str) -> int:
    """解析 Excel 并幂等批量写入 events（分块查重，避免 N+1）。返回新增条数。"""
    init_db()
    events = parse_sangfor(path) or parse_ipguard_excel(path)  # 自动识别深信服 / IP-Guard
    if not events:
        return 0
    events = aggregate(events)  # 网页日志降噪 + 聚合（几万条 → 几千条再入库/研判）
    s = Session()
    try:
        hashes = [e.event_hash() for e in events]
        existing = set()
        for i in range(0, len(hashes), 400):  # 分块，避开 SQLite 参数上限
            batch = hashes[i:i + 400]
            existing.update(r[0] for r in
                            s.query(EventRow.event_hash).filter(EventRow.event_hash.in_(batch)).all())
        added = 0
        for e, h in zip(events, hashes):
            if h in existing or (e.employee_id or "").isdigit() or (e.employee_id or "") in _ignored_employees():  # 跳过已存在 + 访客(纯数字) + 忽略名单
                continue
            s.add(EventRow(event_hash=h, occurred_at=e.occurred_at, employee_id=e.employee_id,
                           device_id=e.device_id, category=e.category, action=e.action,
                           target_type=e.target_type, target_value=e.target_value,
                           size_bytes=e.size_bytes, count=e.count, source=getattr(e,'source',''), raw=e.raw))
            added += 1
        s.commit()
        return added
    finally:
        s.close()


def ingest_events(events) -> int:
    """直接入库一批标准事件（syslog 实时用）：降噪聚合 → 批量幂等写入。返回新增条数。"""
    init_db()
    events = aggregate(events)
    if not events:
        return 0
    s = Session()
    try:
        hashes = [e.event_hash() for e in events]
        existing = set()
        for i in range(0, len(hashes), 400):
            existing.update(r[0] for r in
                            s.query(EventRow.event_hash).filter(EventRow.event_hash.in_(hashes[i:i + 400])).all())
        added = 0
        ignored = _ignored_employees()
        for e, h in zip(events, hashes):
            if h in existing or (e.employee_id or "").isdigit() or (e.employee_id or "") in ignored:  # 跳过已存在 + 访客(纯数字) + 忽略名单
                continue
            s.add(EventRow(event_hash=h, occurred_at=e.occurred_at, employee_id=e.employee_id,
                           device_id=e.device_id, category=e.category, action=e.action,
                           target_type=e.target_type, target_value=e.target_value,
                           size_bytes=e.size_bytes, count=e.count, source=e.source, raw=e.raw))
            added += 1
        s.commit()
        return added
    finally:
        s.close()


def run_detection(risk_threshold: int = 50, on_progress=None) -> tuple[int, int]:
    """增量研判（3 阶段；写锁只在第 3 阶段批量写时短暂持有，可与入库并发）：
    1) 只读：取新事件、建窗口、算历史基线、去重 → 收集待研判窗口
    2) LLM：逐窗口研判（不持写锁）
    3) 写入：一个短事务批量落 verdicts/alerts + 推进水位
    """
    init_db()
    # ---- 1) 读取阶段（只读 session，不持写锁）----
    rs = Session()
    try:
        wm = int(dicts.get_setting("last_judged_event_id", "0") or "0")
        new_rows = rs.query(EventRow).filter(EventRow.id > wm).order_by(EventRow.occurred_at).all()
        # 过滤访客（纯数字手机号/guest）+ 忽略名单（测试账号等）——不是正式员工
        ignored = _ignored_employees()
        new_rows = [r for r in new_rows
                    if not re.match(r'^\d{8,}$', r.employee_id or '')
                    and (r.employee_id or '') not in ignored]
        if not new_rows:
            return 0, _alert_count()
        new_events = [CanonicalEvent(
            occurred_at=r.occurred_at, employee_id=r.employee_id, device_id=r.device_id,
            category=r.category, action=r.action, target_type=r.target_type or "FILE",
            target_value=r.target_value or "", size_bytes=r.size_bytes or 0, count=r.count or 1,
            source=r.source or "", raw=r.raw or {}) for r in new_rows]
        max_id = max(r.id for r in new_rows)
        gdomains = profiles.global_common_domains(rs)
        gctx = profiles.global_summary(rs)  # 全局参照：每轮算一次，喂给所有窗口的 AI
        dedup_hours = int(dicts.get_setting("dedup_window_hours", "6") or "6")
        to_judge = []
        for emp, wins in detector.build_windows(new_events).items():
            for w in wins:
                baseline = profiles.baseline_for(rs, emp, w[0].occurred_at)
                dev = detector.deviation(w, baseline, global_domains=gdomains)
                if not detector.should_trigger(w, dev, baseline):
                    continue
                if rs.query(VerdictRow).filter_by(employee_id=emp, window_start=w[0].occurred_at,
                                                  window_end=w[-1].occurred_at).first():
                    continue
                # 同员工 + 同高危域名 + 近 N 小时已研判过 → 抑制(防 VPN 后台持续连接反复研判)
                trig = _window_trigger_domains(w)
                if trig and _recently_judged(rs, emp, trig, dedup_hours):
                    continue
                to_judge.append((emp, w, baseline, dev))
    finally:
        rs.close()

    if on_progress:
        on_progress("total", len(to_judge))

    # ---- 2) LLM + 增量批量写入：每判 BATCH 个就短事务落库一次 ----
    #    研判期间数据可见、断点可续；写锁只在每个小批的毫秒级持有，不阻塞并发入库。
    BATCH = 10
    buf = []
    judged = 0

    def _flush():
        nonlocal judged
        if not buf:
            return
        wsession = Session()
        try:
            for emp, device, wstart, wend, hashes, v in buf:
                vr = VerdictRow(employee_id=emp, device=device, window_start=wstart, window_end=wend,
                    intent=v.get("intent"), deviation=v.get("deviation"), risk_score=v.get("risk_score", 0),
                    explanation=v.get("explanation"), channels=v.get("channels"),
                    ai_participated=1 if v.get("ai_participated", True) else 0, event_hashes=hashes, model="Qwen3-32B")
                wsession.add(vr); wsession.flush()
                if v.get("risk_score", 0) >= risk_threshold:
                    _exc = wsession.query(ExceptionRow).filter(
                        ExceptionRow.employee_id == emp, ExceptionRow.signal_type == v.get("intent"),
                        (ExceptionRow.expires_at.is_(None)) | (ExceptionRow.expires_at > datetime.utcnow())
                    ).first()
                    if _exc:
                        continue
                    key = f"{emp}|{v.get('intent')}"  # 同员工同意图只保留1条(跨日/跨窗口合并),取最高分+最新
                    existing = wsession.query(AlertRow).filter_by(dedup_key=key).first()
                    if not existing:
                        wsession.add(AlertRow(employee_id=emp, scenario=v.get("intent"),
                            severity=severity_of(v.get("risk_score", 0)), risk_score=v.get("risk_score", 0),
                            verdict_id=vr.id, summary=v.get("explanation"), dedup_key=key, window_start=wstart))
                        if v.get("risk_score", 0) >= 75:
                            _notify_webhook(emp, v.get("risk_score", 0), v.get("explanation", ""))
                    elif v.get("risk_score", 0) > (existing.risk_score or 0):
                        existing.risk_score = v.get("risk_score", 0)
                        existing.severity = severity_of(v.get("risk_score", 0))
                        existing.summary = v.get("explanation")
                        existing.verdict_id = vr.id
                        existing.window_start = wstart
            wsession.commit()
        finally:
            wsession.close()
        judged += len(buf)
        buf.clear()

    # ---- 2) LLM 并发研判（4线程并发，vLLM内部batch → 3-4倍提速）----
    def _judge(item):
        emp, w, baseline, dev = item
        summary = profiles.summarize_for_llm(baseline)  # 冷启动返回 None（由 analyze_window 喂全局参照）
        # 查该用户是否有豁免（已确认正常的行为），传给 AI 作为上下文
        exempt = None
        try:
            from datetime import datetime as _dt
            es = Session()
            try:
                # expires_at 用 utcnow+days 写入，这里同源比较（不走 occurred_at 的北京时区）
                exs = es.query(ExceptionRow).filter(
                    ExceptionRow.employee_id == emp,
                    (ExceptionRow.expires_at.is_(None)) | (ExceptionRow.expires_at > _dt.utcnow())
                ).all()
            finally:
                es.close()
            if exs:
                exempt = "; ".join(f"{INTENT_MAP.get(e.signal_type, e.signal_type)}({e.reason})" for e in exs)
        except Exception:
            pass
        v = detector.analyze_window(w, summary, dev, exempt, gctx)
        return (emp, w[0].device_id, w[0].occurred_at, w[-1].occurred_at, [e.event_hash() for e in w], v)

    done_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futs = {pool.submit(_judge, item): i for i, item in enumerate(to_judge)}
        for fut in concurrent.futures.as_completed(futs):
            try:
                buf.append(fut.result())
            except Exception:
                pass  # 单个窗口失败不影响整体
            done_count += 1
            if on_progress:
                on_progress("done", done_count)
            if len(buf) >= BATCH:
                _flush()
    _flush()  # 收尾剩余

    # ---- 3) 推进研判水位 ----
    ws = Session()
    try:
        wm_row = ws.query(SettingRow).filter_by(key="last_judged_event_id").first()
        if wm_row:
            wm_row.value = str(max_id)
        else:
            ws.add(SettingRow(key="last_judged_event_id", value=str(max_id)))
        ws.commit()
    finally:
        ws.close()
    return judged, _alert_count()


# ---- 单飞异步研判：同一时刻只跑一个；后台线程执行，前端轮询进度 ----
_detect_lock = threading.Lock()
_detect_status = {"running": False, "total": 0, "done": 0, "judged": 0, "alerts": 0, "error": None,
                  "last_finished": None, "last_judged": 0, "last_alerts": 0}


def detection_status() -> dict:
    return dict(_detect_status)


def start_detection(risk_threshold: int = 50) -> dict:
    """启动后台研判（单飞）。已在跑则返回 busy，不重复启动。"""
    if not _detect_lock.acquire(blocking=False):
        return {"running": True, "busy": True, **detection_status()}

    def _worker():
        try:
            _detect_status.update(running=True, total=0, done=0, judged=0, alerts=0, error=None)

            def _prog(kind, val):
                _detect_status["total" if kind == "total" else "done"] = val

            judged, alerts = run_detection(risk_threshold, on_progress=_prog)
            _detect_status.update(running=False, judged=judged, alerts=alerts,
                                  last_finished=datetime.utcnow().isoformat(),
                                  last_judged=judged, last_alerts=alerts)
        except Exception as e:
            _detect_status.update(running=False, error=str(e))
        finally:
            _detect_lock.release()

    threading.Thread(target=_worker, daemon=True).start()
    return detection_status()


def auto_close_alerts():
    """自动关闭低风险/过期的告警（不影响基线和研判，只是清理运营视图）。
    - baseline_deviation + risk<50 → 立即关闭（噪音）
    - baseline_deviation + risk 50-65 + 超过3天 → 关闭（冷启动过期）
    - 其他 → 不动（需人工处理）
    """
    from datetime import datetime, timedelta
    init_db()
    s = Session()
    try:
        now = datetime.utcnow()
        cutoff_3d = now - timedelta(days=3)
        # 立即关闭：偏离类 + 低分
        n1 = s.query(AlertRow).filter(
            AlertRow.scenario == "baseline_deviation",
            AlertRow.risk_score < 50,
            AlertRow.status == "NEW"
        ).update({AlertRow.status: "CLOSED"}, synchronize_session=False)
        # 3天后关闭：偏离类 + 中分 + 超时
        n2 = s.query(AlertRow).filter(
            AlertRow.scenario == "baseline_deviation",
            AlertRow.risk_score >= 50,
            AlertRow.risk_score < 66,
            AlertRow.status == "NEW",
            AlertRow.created_at < cutoff_3d
        ).update({AlertRow.status: "CLOSED"}, synchronize_session=False)
        s.commit()
        return n1 + n2
    finally:
        s.close()


def cleanup_old_events(days: int = 90) -> int:
    """清理超过保留期的事件（告警/研判记录保留）。返回删除条数。"""
    from datetime import timedelta
    init_db()
    s = Session()
    try:
        cutoff = bj_now() - timedelta(days=days)  # occurred_at 是北京时间，按本地算保留期
        n = s.query(EventRow).filter(EventRow.occurred_at < cutoff).delete(synchronize_session=False)
        s.commit()
        return n
    finally:
        s.close()


def cleanup_old_raw_logs(days: int = 7) -> int:
    """清理超过保留期的原始 syslog 报文(raw_logs)。

    raw_logs 是深信服推送的报文原文,仅用于排查"推送了什么"。
    长期累积体积大(约 7万条/天)且历史价值低——events 已做降噪聚合,
    verdicts/alerts 记录了研判结果。默认 7 天,可经 setting raw_logs_retention_days 调。
    与 events 的 90 天保留分离(events 是分析基础,raw_logs 只为近期排查)。
    """
    from datetime import timedelta
    init_db()
    s = Session()
    try:
        from db import RawLogRow
        cutoff = bj_now() - timedelta(days=days)
        n = s.query(RawLogRow).filter(RawLogRow.received_at < cutoff).delete(synchronize_session=False)
        s.commit()
        return n
    finally:
        s.close()


def _notify_webhook(user: str, risk: int, explanation: str):
    """高危告警推送到钉钉/飞书/企业微信 webhook。"""
    import json
    import urllib.request
    url = dicts.get_setting("notify_webhook", "")
    if not url:
        return
    try:
        body = json.dumps({"msgtype": "text", "text": {"content": f"IP-Guard 高危告警\n用户: {user}\n风险: {risk}\n说明: {explanation}"}}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


def rejudge_all(risk_threshold: int = 50) -> dict:
    """清空 verdicts/alerts + 重置研判水位 → 异步重新研判全部历史（修复模型/prompt 后重跑用）。"""
    init_db()
    s = Session()
    try:
        s.query(VerdictRow).delete()
        s.query(AlertRow).delete()
        wm = s.query(SettingRow).filter_by(key="last_judged_event_id").first()
        if wm:
            wm.value = "0"
        else:
            s.add(SettingRow(key="last_judged_event_id", value="0"))
        s.commit()
    finally:
        s.close()
    return start_detection(risk_threshold)


def run_all(path: str) -> tuple[int, int, int]:
    """CLI 一键：导入 → 建画像 → 同步研判。"""
    n = ingest_file(path)
    profiles.build_profiles()
    nv, na = run_detection()
    return n, nv, na


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\huxi\Desktop\111.xlsx"
    n, nv, na = run_all(path)
    print(f"导入 {n} 条事件；研判 {nv} 个窗口；库内告警 {na} 条")
