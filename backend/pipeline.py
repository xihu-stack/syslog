"""流水线编排：批量导入 → 建画像 → 增量研判（3 阶段，研判时不持写锁）→ 单飞异步。"""
from __future__ import annotations

import concurrent.futures
from datetime import datetime, timedelta
import re
import sys
import threading

from db import (AlertRow, EventRow, ExceptionRow, Session, SettingRow, VerdictRow,
                bj_now, init_db, severity_of, write_lock)
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
    """直接入库一批标准事件（syslog 实时用）：降噪聚合 → 用户名统一 → 批量幂等写入。返回新增条数。"""
    init_db()
    events = aggregate(events)
    if not events:
        return 0
    try:  # 用户标识统一: 确认过的映射(账号/IP标识->中文名)入库前转换,新数据天然统一
        import json as _js
        _alias = _js.loads(dicts.get_setting("employee_alias") or "{}")
        if _alias:
            for e in events:
                e.employee_id = _alias.get(e.employee_id or "", e.employee_id)
    except Exception:
        pass
    with write_lock:  # 与研判 _flush 串行写，避免写锁互等报 database is locked
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
        import time as _t0
        _T = _t0.time()
        print(f"[detect] 读取阶段开始 wm={wm}", flush=True)
        new_rows = rs.query(EventRow).filter(EventRow.id > wm).order_by(EventRow.occurred_at).all()
        print(f"[detect] 读取完成 {len(new_rows)}行 耗{_t0.time()-_T:.1f}s", flush=True)
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
        gctx = profiles.global_summary(rs)
        print(f"[detect] 全局参照完成 耗{_t0.time()-_T:.1f}s", flush=True)  # 全局参照：每轮算一次，喂给所有窗口的 AI
        dedup_hours = int(dicts.get_setting("dedup_window_hours", "6") or "6")
        to_judge = []
        _run_seen = set()  # 轮内去重:(员工,高危域名) 已排队送AI的,同轮不再重复判
        _base_cache = {}  # (员工, 日期)→基线: 同员工同天的窗口共享一份。全量重判时
        # 3000+窗口逐个重算基线(每人查全量事件+算画像)会拖到几十分钟(2026-08-19实测卡死)
        for emp, wins in detector.build_windows(new_events).items():
            for w in wins:
                _bk = (emp, w[0].occurred_at.date())
                if _bk not in _base_cache:
                    _base_cache[_bk] = profiles.baseline_for(rs, emp, w[0].occurred_at)
                baseline = _base_cache[_bk]
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
                # 轮内抑制:筛选阶段同轮窗口互相看不到已落库的verdicts,
                # 不拦的话同域名多窗口会全部重复送LLM(浪费调用+研判刷屏)
                if trig and any((emp, d) in _run_seen for d in trig):
                    continue
                if trig:
                    _run_seen.update((emp, d) for d in trig)
                to_judge.append((emp, w, baseline, dev))
    finally:
        rs.close()

    print(f"[detect] 窗口筛选完成 to_judge={len(to_judge)} 耗{_t0.time()-_T:.1f}s", flush=True)
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
        from sqlalchemy.exc import OperationalError as _OpErr
        import time as _time
        # write_lock：与 syslog 的 ingest_events/build_profiles 串行写，根除 database is locked。
        # 重试：兜底——即便有别处未加锁的写或 WAL 边界情况，也只重试不中断整个研判。
        with write_lock:
            for attempt in range(30):
                wsession = Session()
                try:
                    import llm_client as _lc
                    for emp, device, wstart, wend, hashes, v in buf:
                        vr = VerdictRow(employee_id=emp, device=device, window_start=wstart, window_end=wend,
                            intent=v.get("intent"), deviation=v.get("deviation"), risk_score=v.get("risk_score", 0),
                            explanation=v.get("explanation"), channels=v.get("channels"),
                            ai_participated=1 if v.get("ai_participated", True) else 0, event_hashes=hashes,
                            model=(_lc.LAST_MODEL or "unknown") if v.get("ai_participated", True) else "rule-fallback")
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
                            else:
                                # 已有告警:当天再犯即刷新最近活动时间(window_start),让"今日告警"/趋势图
                                # 如实反映当日复犯;分数只升不降(取峰值)。
                                existing.window_start = wstart
                                # 再犯重新待处理:已确认/误报的告警再次触发时重置为NEW——
                                # 否则确认一次=对该意图永久静默,复犯永远不再提醒(2026-08-18用户发现)。
                                # 处置历史不丢:确认/误报时都写了feedback表留痕。
                                _was = existing.status
                                if _was and _was != "NEW":
                                    existing.status = "NEW"
                                    if v.get("risk_score", 0) >= 75:
                                        _notify_webhook(f"{emp}(复犯,原状态{_was})", v.get("risk_score", 0),
                                                        v.get("explanation", ""))
                                # 内容与时间同步: verdict_id/summary 指向本次(最新)窗口的研判——
                                # 否则window_start刷到今天、说明还是老窗口的行为,今日告警展示昨天的内容(2026-08-18审计发现)
                                # summary 必须与verdict_id无条件同步: 常态复犯(一直NEW且未破峰值)时
                                # 若只在状态重置/破峰值时刷,会出现分数指向最新窗口、说明停留在旧文案
                                # (2026-08-19夏玮案例: 75分告警挂着"复核降级35分"的过期说明)
                                existing.verdict_id = vr.id
                                existing.summary = v.get("explanation") or existing.summary
                                # 分数=最新告警级研判分,与说明/研判历史同源。废除"只升不降取峰值":
                                # 峰值口径造成列表78分/说明里55分两个数字对不上(2026-08-19逐告警
                                # 核对发现15条不一致);历史峰值在研判历史里仍可见
                                existing.risk_score = v.get("risk_score", 0)
                                existing.severity = severity_of(v.get("risk_score", 0))
                    wsession.commit()
                    break  # 提交成功
                except _OpErr as e:
                    wsession.rollback()
                    if "locked" in str(e).lower() and attempt < 29:
                        _time.sleep(1)
                        continue
                    raise  # 非锁冲突 或 重试耗尽，抛出
                finally:
                    wsession.close()
        judged += len(buf)
        buf.clear()

    # ---- 2) LLM 并发研判（4线程并发，vLLM内部batch → 3-4倍提速）----
    # 员工近7天行为史缓存(跨天模式关联: 连续多日重复/频率爬坡/敏感文档+招聘组合)
    _hist_cache = {}

    def _emp_history(emp: str) -> str:
        if emp in _hist_cache:
            return _hist_cache[emp]
        txt = ""
        try:
            from datetime import timedelta as _td4
            from collections import defaultdict as _dd3
            import dicts as _dc
            hs = Session()
            try:
                since7 = bj_now() - _td4(days=7)
                vs = hs.query(VerdictRow).filter(
                    VerdictRow.employee_id == emp, VerdictRow.window_start >= since7
                ).order_by(VerdictRow.window_start).all()
                from db import json_field as _jf
                dom_e = _jf(EventRow.raw, 'domain')
                evs = hs.query(EventRow.occurred_at, dom_e, EventRow.category, EventRow.target_value).filter(
                    EventRow.employee_id == emp, EventRow.occurred_at >= since7).all()
                parts = []
                if vs:
                    from collections import Counter as _ct
                    ic = _ct(v.intent for v in vs)
                    parts.append("研判史: " + "; ".join(f"{INTENT_MAP.get(k, k)}×{n}次(最高{max((x.risk_score or 0) for x in vs if x.intent == k)}分)" for k, n in ic.items()))
                by_day_label = _dd3(lambda: _dd3(int))
                docs = []
                for occ, dom, cat, tv in evs:
                    if not occ:
                        continue
                    d = (dom or "").lower()
                    if cat == "WEB" and d:
                        rc = _dc.risk_class(d)
                        if rc:
                            by_day_label[rc][occ.strftime("%m-%d")] += 1
                    elif cat == "DOC" and tv:
                        for kw in (_dc.get("sensitive_keywords") or []):
                            if kw in tv:
                                docs.append(f"{occ.strftime('%m-%d')} {tv[:40]}")
                                break
                if by_day_label:
                    lines = []
                    for lab, days in by_day_label.items():
                        seq = ", ".join(f"{d}×{n}" for d, n in sorted(days.items()))
                        consec = len(days)
                        # 显式升档提示: AI对"每天仅1次"的跨天累计不敏感,必须点名规则①
                        hint = f"【⚠跨天规则①命中: 累计{consec}天≥4天,即使每天仅1次也属进行中行为,必须升档】" if consec >= 4 else ""
                        lines.append(f"{lab}: {seq} (共{consec}天){hint}")
                    parts.append("风险类访问按天: " + "; ".join(lines))
                if docs:
                    parts.append("敏感文档操作: " + "; ".join(docs[:5]))
                txt = "\n【近7天行为史】(跨天模式关联用,判断是否'进行中行为')\n" + "\n".join("  " + p for p in parts) if parts else ""
            finally:
                hs.close()
        except Exception as _he:
            print(f"[hist] {emp} 行为史查询失败: {_he}", flush=True)
        _hist_cache[emp] = txt
        return txt

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
        _hist = _emp_history(emp)
        # 当日累计(截至研判): 窗口内高危域名的全天累计次数——窗口只是60分钟切片,
        # 单窗口3次但全天10次的情况只写窗口数会让人误读(2026-08-19用户发现)
        day_ctx = None
        _day_tot = None
        _day_mj = _day_gn = 0  # 当日重点/一般招聘站累计(招聘锚点用当日口径定档,
        # 高聪20次智联分散多窗口,单窗口9次只到70档,当日13次才到高频80档)
        _MJ_KW = ("zhipin", "liepin", "51job", "zhaopin", "sndhr")
        try:
            _domset = {(((e.raw or {}).get("domain") or "")).lower() for e in w
                       if e.category == "WEB" and dicts.risk_tier((e.raw or {}).get("domain") or "") in ("high", "mid", "job")}
            if _domset:
                _d0 = w[0].occurred_at.replace(hour=0, minute=0, second=0, microsecond=0)
                _d1 = _d0 + timedelta(days=1)
                _agg = {}
                ds = Session()
                try:
                    for e in ds.query(EventRow).filter(EventRow.employee_id == emp,
                                                       EventRow.occurred_at >= _d0,
                                                       EventRow.occurred_at < _d1).all():
                        d = ((e.raw or {}).get("domain") or "").lower()
                        if d in _domset:
                            _agg[d] = _agg.get(d, 0) + (e.count or 1)
                finally:
                    ds.close()
                if _agg:
                    _day_tot = sum(_agg.values())
                    for d, n in _agg.items():
                        if dicts.risk_tier(d) == "job":
                            if any(m in d for m in _MJ_KW):
                                _day_mj += n
                            else:
                                _day_gn += n
                    # 家族(按风险类别)累计: AI按完整域名报数会漏子域(高聪sndhr
                    # 实际13次AI只报主域9次,2026-08-19复审发现),给类别合计供引用
                    _fam = {}
                    for d, n in _agg.items():
                        rc = dicts.risk_class(d) or d
                        _fam[rc] = _fam.get(rc, 0) + n
                    fam_txt = ", ".join(f"{k}类合计{v2}次" for k, v2 in sorted(_fam.items(), key=lambda x: -x[1]))
                    day_ctx = ("[当日累计(截至本研判,含全部子域)] " +
                               ", ".join(f"{d}×{n}" for d, n in sorted(_agg.items(), key=lambda x: -x[1])[:6]) +
                               "; " + fam_txt)
        except Exception:
            pass
        v = detector.analyze_window(w, summary, dev, exempt, gctx, history=_hist, day_ctx=day_ctx)
        # ---- 锚点接管: 访问即违规类(policy/data)分数统一按客观特征计算 ----
        # 同样的问题必须同分(2026-08-19用户要求);LLM分<30视为遥测等例外,不接管
        _anchored = None
        if isinstance(v, dict) and (v.get("risk_score") or 0) >= 30:
            _a = detector.anchor_score(v.get("intent"), w, day_total=_day_tot)
            if _a is not None:
                v = {**v, "risk_score": _a}
                _anchored = _a
        # ---- 招聘锚点: 程序化定分,AI只负责行为描述 ----
        # 重点站(BOSS/猎聘/51job/智联sndhr)——第一优先级场景(2026-08-19用户口径):
        #   单次(1-2次)=65; 反复3-9次=80; 高频≥10次=85(全系统最高档,高于外发);
        # 一般站(领英等)——"关注即可,分数不用太高":
        #   单次=15正常; 反复3-9次=55; 高频≥10次=60; 跨天(≥4天,每天1次也算)=55;
        # 修正: 凌晨+5 / 跨天+5 / 封顶95(重点)、65(一般)。
        # AI判job_seeking但一般站单次无凌晨无跨天 → 强制压回normal(叶珂祯案例防线)。
        if isinstance(v, dict) and _anchored is None:
            _MAJOR = ("zhipin", "liepin", "51job", "zhaopin", "sndhr")
            _mj, _gn = 0, 0
            for e in w:
                if e.category != "WEB":
                    continue
                _d = (((e.raw or {}).get("domain") or "").lower())
                if dicts.risk_tier(_d) != "job":
                    continue
                if any(m in _d for m in _MAJOR):
                    _mj += (e.count or 1)
                else:
                    _gn += (e.count or 1)
            if _mj or _gn:
                _off = any(detector._is_off_hours(e.occurred_at) for e in w)
                _xd = "跨天规则①命中" in (_hist or "")
                _mj = max(_mj, _day_mj)  # 档位按当日累计定(高聪案例:分散多窗口不降档)
                _gn = max(_gn, _day_gn)
                if _mj >= 1:
                    if _mj >= 10:
                        _js = 85
                    elif _mj >= 3:
                        _js = 80
                    else:
                        _js = 65
                    v = {**v, "intent": "job_seeking",
                         "risk_score": min(_js + (5 if _off else 0) + (5 if _xd else 0), 95)}
                elif _gn >= 3 or (_gn >= 1 and _xd):
                    _js = 60 if _gn >= 10 else 55
                    v = {**v, "intent": "job_seeking",
                         "risk_score": min(_js + (5 if _off else 0) + (5 if _xd else 0), 65)}
                elif v.get("intent") == "job_seeking" and not _off and not _xd:
                    v = {**v, "intent": "normal_work", "risk_score": 15}
        # ---- 双模型复核: Qwen判定达到告警级(≥阈值)时,用深度模型独立重判一遍。
        # 两模型一致才维持告警;复核明显更低则降级(证据撑不起告警)。复核失败保守
        # 保留原判。说明不写复核过程,直接给结论(2026-08-19用户要求)。
        try:
            _smart = _lc_smart()
            if _smart and isinstance(v, dict) and (v.get("risk_score") or 0) >= 50 \
                    and dicts.get_setting("llm_review", "1") == "1":
                rv = detector.analyze_window(w, summary, dev, exempt, gctx, model=_smart, history=_hist, day_ctx=day_ctx)
                rs = (rv or {}).get("risk_score") or 0
                q = v.get("risk_score") or 0
                if rs >= 50:  # 一致 → 维持;锚点场景用锚点分,其余取深模型说明+较高分
                    v = {**rv, "risk_score": _anchored if _anchored is not None else max(q, rs)}
                else:  # 分歧 → 降级到复核分(锚点不再适用,证据已被复核否定)
                    v = {**v, "risk_score": max(rs, 30)}
        except Exception:
            pass  # 复核异常不影响主判
        return (emp, w[0].device_id, w[0].occurred_at, w[-1].occurred_at, [e.event_hash() for e in w], v)

    def _lc_smart():
        import llm_client
        return llm_client.smart_model()

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
    with write_lock:  # 串行写，避免收尾时写锁冲突导致整轮研判前功尽弃
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
                                  last_finished=bj_now().isoformat(),  # 北京时间,前端直接显示(旧utcnow差8h)
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
        now = bj_now()  # created_at 存的是北京时间,同源比较(旧版utcnow导致3天关闭晚8小时)
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
    """重置研判水位到7天前 → 异步按当前规则重判近7天(修复模型/prompt后重跑用)。
    告警行保留: 重判后复犯刷新逻辑会更新分数/说明/verdict_id,而状态(已知晓/误报)
    不动——用户处置历史不丢(2026-08-19改造;旧版删告警导致处置状态全重置)。
    范围限近7天: 全量历史回放窗口过万会拖死(2026-08-19实测),且告警/TOP均为7天口径。"""
    from datetime import timedelta as _td5
    init_db()
    s = Session()
    try:
        s.query(VerdictRow).delete()
        row = s.query(EventRow).filter(EventRow.occurred_at >= bj_now() - _td5(days=7)) \
            .order_by(EventRow.id).first()
        wm_val = str(row.id) if row else "0"
        wm = s.query(SettingRow).filter_by(key="last_judged_event_id").first()
        if wm:
            wm.value = wm_val
        else:
            s.add(SettingRow(key="last_judged_event_id", value=wm_val))
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
