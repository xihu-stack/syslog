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
        elif e.category == "DOC" and e.action in ("UPLOAD", "SEND", "PRINT", "BURN"):
            # DOC外发伪域名去重键: IPG接入后防止同员工同类外发动作反复送LLM
            ch = (e.raw or {}).get("channel")
            doms.add(f"doc:{e.action}:{ch or 'LOCAL'}")
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


def _pipestat(**kw):
    """链路埋点(2026-08-25数据链路页): 每日settings计数器 pipestat_YYYYMMDD。"""
    try:
        import json as _j2
        key = f"pipestat_{bj_now().strftime('%Y%m%d')}"
        cur = {}
        try:
            cur = _j2.loads(dicts.get_setting(key) or "{}")
        except Exception:
            cur = {}
        for k, v in kw.items():
            cur[k] = (cur.get(k) or 0) + v
        dicts.set_setting(key, _j2.dumps(cur, ensure_ascii=False))
    except Exception:
        pass


def ingest_events(events) -> int:
    """直接入库一批标准事件（syslog 实时用）：降噪聚合 → 用户名统一 → 批量幂等写入。返回新增条数。"""
    init_db()
    _web_in = sum(1 for e in events if e.category == "WEB")
    events = aggregate(events)
    _web_out = sum(1 for e in events if e.category == "WEB")
    _pipestat(raw_in=len(events), web_in=_web_in,
              noise_or_merged=max(_web_in - _web_out, 0) + max(_web_out - _web_in, 0))
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
    # 跨源网页去重(2026-08-20 IPG接入): IPG的url_log与深信服重复覆盖同一浏览,
    # 同员工同域名10分钟内已有任一来源事件 → 丢弃IPG副本(避免效率/事件量双计)
    # 对称化(2026-08-24): 原只查"IPG副本是否与已入库深信服重复"——IPG先到30秒、
    # 深信服后到时同一浏览双计(实测8对: 夏玮xft/黄春煜italent等),效率与风险次数被抬高
    _sf_web = [e for e in events if getattr(e, "source", "") != "ipguard" and e.category == "WEB"]
    if _sf_web:
        try:
            from datetime import timedelta as _td3
            _keys3 = {(e.employee_id, ((e.raw or {}).get("domain") or "").lower()) for e in _sf_web}
            _emps3 = {k[0] for k in _keys3}
            _cand3 = set()
            s3 = Session()
            try:
                for _r in s3.query(EventRow.employee_id, EventRow.raw).filter(
                        EventRow.employee_id.in_(list(_emps3)[:100]),
                        EventRow.category == "WEB",
                        EventRow.source == "ipguard",
                        EventRow.occurred_at >= bj_now() - _td3(minutes=10)).all():
                    _d = ((_r.raw or {}).get("domain") or "").lower() if isinstance(_r.raw, dict) else ""
                    if _d:
                        _cand3.add((_r.employee_id, _d))
            finally:
                s3.close()
            if _cand3:
                _b3 = len(events)
                events = [e for e in events if not (
                    getattr(e, "source", "") != "ipguard" and e.category == "WEB"
                    and (e.employee_id, ((e.raw or {}).get("domain") or "").lower()) in _cand3)]
                if _b3 - len(events):
                    _pipestat(cross_dedup=_b3 - len(events))
                    print(f"[ingest] 反向去重: {_b3 - len(events)}条深信服副本跳过(IPG已记录)", flush=True)
        except Exception:
            pass
    _ipg_web = [e for e in events if getattr(e, "source", "") == "ipguard" and e.category == "WEB"]
    if _ipg_web:
        try:
            from datetime import timedelta as _td2
            _keys = {(e.employee_id, ((e.raw or {}).get("domain") or "").lower()) for e in _ipg_web}
            _emps = {k[0] for k in _keys}
            _cand = set()
            s2 = Session()
            try:
                for _r in s2.query(EventRow.employee_id, EventRow.raw).filter(
                        EventRow.employee_id.in_(list(_emps)[:100]),
                        EventRow.category == "WEB",
                        EventRow.occurred_at >= bj_now() - _td2(minutes=10)).all():
                    _d = ((_r.raw or {}).get("domain") or "").lower() if isinstance(_r.raw, dict) else ""
                    if _d:
                        _cand.add((_r.employee_id, _d))
            finally:
                s2.close()
            if _cand:
                _before = len(events)
                events = [e for e in events if not (
                    getattr(e, "source", "") == "ipguard" and e.category == "WEB"
                    and (e.employee_id, ((e.raw or {}).get("domain") or "").lower()) in _cand)]
                _pipestat(cross_dedup=_before - len(events))
                print(f"[ingest] 跨源网页去重: {_before - len(events)}条IPG副本跳过", flush=True)
        except Exception:
            pass
    with write_lock:  # 与研判 _flush 串行写，避免写锁互等报 database is locked
        s = Session()
        try:
            hashes = [e.event_hash() for e in events]
            existing = {}
            for i in range(0, len(hashes), 400):
                existing.update({r.event_hash: r for r in
                                 s.query(EventRow).filter(EventRow.event_hash.in_(hashes[i:i + 400])).all()})
            added = 0
            ignored = _ignored_employees()
            seen = set()  # 批内去重: 同批两条相同hash(深信服重发/聚合边界重叠)会撞
            for e, h in zip(events, hashes):    # UNIQUE约束且整批回滚丢数据(2026-08-20)
                if (e.employee_id or "").isdigit() or (e.employee_id or "") in ignored:
                    continue
                if h in existing:  # 同桶已入库(10分钟桶跨30秒批次): count累加——
                    # 原直接跳过导致outlook.live.com 21行全count=1,频次类口径系统性低估
                    # (锚点中频/高频加分、跨天模式、效率统计全偏低,2026-08-24实测)
                    row = existing[h]
                    row.count = (row.count or 0) + (e.count or 1)
                    _rv = dict(row.raw or {})  # 拷贝后重赋值(JSON列原地改不被变更追踪)
                    _rv["visit_count"] = row.count
                    _er = e.raw or {}
                    for _t2 in (_er.get("titles") or []):  # 后续批次的桶内语义证据合并
                        _ts = _rv.setdefault("titles", [])
                        if _t2 not in _ts and len(_ts) < 2:
                            _ts.append(_t2)
                    for _u2 in (_er.get("url_samples") or []):
                        _us = _rv.setdefault("url_samples", [])
                        if _u2 not in _us and len(_us) < 2:
                            _us.append(_u2)
                    row.raw = _rv
                    added += 1  # 计入"有新活动",让画像/研判照常触发
                    continue
                if h in seen:
                    continue
                seen.add(h)
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
        _detect_status.update(phase="筛选风险窗口(约1-5分钟,此时进度为0属正常)")
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
        _id_by_hash = {e.event_hash(): r.id for r, e in zip(new_rows, new_events)}
        _held_min_id = None  # 证据等待(2026-08-26朱亮案例): 空目的地上传窗口扣留12分钟
        _HOLD = timedelta(minutes=12)  # 等深信服延迟批(实测~7分钟)到齐再判,目的地可见
        gdomains = profiles.global_common_domains(rs)
        gctx = profiles.global_summary(rs)
        print(f"[detect] 全局参照完成 耗{_t0.time()-_T:.1f}s", flush=True)  # 全局参照：每轮算一次，喂给所有窗口的 AI
        dedup_hours = int(dicts.get_setting("dedup_window_hours", "6") or "6")
        to_judge = []
        _sup = {}  # 抑制原因计数(数据链路页展示"为什么没送AI")
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
                # 证据等待: 窗口含空目的地DOC上传(网页上传IPG不记目的地)且窗口刚结束
                # → 深信服浏览数据延迟~7分钟,现在判只能写"目的地未记录";扣到下轮
                # (水位线为扣留窗口让路,事件不会丢),等浏览证据到齐目的地可见再判
                _unk = any(e.category == "DOC" and e.action in ("SEND", "UPLOAD")
                           and not dicts.dest_host(e.raw or {}) for e in w)
                if _unk and (bj_now() - w[-1].occurred_at) < _HOLD:
                    _wids = [_id_by_hash.get(e.event_hash()) for e in w]
                    _wids = [i for i in _wids if i]
                    if _wids:
                        _held_min_id = min(_held_min_id, min(_wids)) if _held_min_id else min(_wids)
                    continue
                if rs.query(VerdictRow).filter_by(employee_id=emp, window_start=w[0].occurred_at,
                                                  window_end=w[-1].occurred_at).first():
                    _sup["已判过"] = _sup.get("已判过", 0) + 1
                    continue
                # 同员工 + 同高危域名 + 近 N 小时已研判过 → 抑制(防 VPN 后台持续连接反复研判)
                trig = _window_trigger_domains(w)
                if trig and _recently_judged(rs, emp, trig, dedup_hours):
                    _sup["6小时去重"] = _sup.get("6小时去重", 0) + 1
                    continue
                # 轮内抑制:筛选阶段同轮窗口互相看不到已落库的verdicts,
                # 不拦的话同域名多窗口会全部重复送LLM(浪费调用+研判刷屏)
                if trig and any((emp, d) in _run_seen for d in trig):
                    continue
                if trig:
                    _run_seen.update((emp, d) for d in trig)
                to_judge.append((emp, w, baseline, dev))
        _pipestat(windows=len(to_judge), **{f"sup_{k}": v for k, v in _sup.items()})
    finally:
        rs.close()

    print(f"[detect] 窗口筛选完成 to_judge={len(to_judge)} 耗{_t0.time()-_T:.1f}s", flush=True)
    _detect_status.update(phase="LLM研判中")
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
                    import llm_client as _lc2

                    def _expl_ok(emp, wstart, v, w):
                        """说明完整度自检(2026-08-26): 5W五要素缺项→用窗口事实模板重写,
                        保证每条说明独立可读(梁瑞'外发:→→'半成品案例)。"""
                        e = str(v.get("explanation") or "")
                        if len(e) < 25:
                            return False
                        has_who = emp[:2] in e or "员工" in e
                        _ds = str(wstart)[5:10]
                        has_time = any(x in e for x in (_ds, "凌晨", "上午", "下午", "工作时段", "深夜", "夜间", "时段"))
                        has_ch = any(x in e for x in ("通过", "经", "exe", "通道"))
                        has_obj = ("『" in e) or ("×" in e) or (".p" in e) or (".x" in e) or (".d" in e) or ("访问" in e)
                        has_q = any(x in e for x in ("属", "风险", "嫌疑", "违规", "正常", "偏离"))
                        return all([has_who, has_time, has_ch, has_obj, has_q])

                    def _factual_expl(emp, w, wstart, v):
                        _sends = [e for e in w if e.category == "DOC" and e.action in ("SEND", "UPLOAD", "PRINT")]
                        _doms = []
                        for e in w:
                            if e.category == "WEB":
                                d = ((e.raw or {}).get("domain") or "").lower()
                                if d and dicts.risk_class(d) and d not in _doms:
                                    _doms.append(d)
                        _t = str(wstart)[5:16].replace("T", " ")
                        _inten = {"data_exfiltration": "数据外发", "policy_violation": "违规访问",
                                  "job_seeking": "求职信号", "baseline_deviation": "行为偏离",
                                  "normal_work": "正常办公"}.get(v.get("intent"), v.get("intent") or "行为")
                        if _sends:
                            _fs = "、".join(f"『{(e.target_value or '未命名')[:36]}』" for e in _sends[:3])
                            _mb = sum((e.size_bytes or 0) for e in _sends) / 1048576
                            _ch = (_sends[0].raw or {}).get("app") or (_sends[0].raw or {}).get("channel") or "网络"
                            return (f"{emp}在{_t}通过{_ch}发送{_fs}共{len(_sends)}个文件"
                                    + (f"({_mb:.1f}MB)" if _mb >= 0.5 else "")
                                    + f",属{_inten}(系统按窗口事实生成)。")
                        if _doms:
                            return f"{emp}在{_t}访问风险域名{'、'.join(_doms[:3])},属{_inten}(系统按窗口事实生成)。"
                        return f"{emp}在{_t}存在{_inten}相关行为(系统按窗口事实生成)。"

                    for emp, device, wstart, wend, hashes, v in buf:
                        # explanation剥离思维链(2026-08-26唐方毅案例: 说明以"好,我现在需要分析"开头
                        # ——deep模型think未剥净即入库);同时清掉角色扮演残留
                        if not _expl_ok(emp, wstart, v, w):
                            v["explanation"] = _factual_expl(emp, w, wstart, v)
                        if v.get("explanation"):
                            _e2 = _lc2.strip_think(str(v["explanation"]))
                            for _bad in ("好，我现在", "好的，我现在", "首先，", "让我分析"):
                                if _e2.startswith(_bad):
                                    _e2 = _e2.split("。", 1)[-1].lstrip()
                            v["explanation"] = _e2
                        # normal_work=系统认定正常业务: 分数钳制≤20,防LLM"结论正常
                        # 但分数80"的自相矛盾(2026-08-24展佳案例:normal_work 80分
                        # 生成告警);正常业务永不进告警队列
                        if v.get("intent") == "normal_work":
                            v["risk_score"] = min(int(v.get("risk_score", 0) or 0), 20)
                        vr = VerdictRow(employee_id=emp, device=device, window_start=wstart, window_end=wend,
                            intent=v.get("intent"), deviation=v.get("deviation"), risk_score=v.get("risk_score", 0),
                            explanation=v.get("explanation"), channels=v.get("channels"),
                            ai_participated=1 if v.get("ai_participated", True) else 0, event_hashes=hashes,
                            model=(_lc.LAST_MODEL or "unknown") if v.get("ai_participated", True) else "rule-fallback")
                        wsession.add(vr); wsession.flush()
                        if v.get("risk_score", 0) >= risk_threshold and v.get("intent") != "normal_work":
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
                                # 推送门控(2026-08-26): 单次低价值不推,只推复合/高分/大体量——
                                # 否则单张截图也轰炸webhook
                                _mb2 = sum((e.size_bytes or 0) for e in w
                                           if e.category == "DOC" and e.action in ("SEND", "UPLOAD")) / 1048576
                                if (v.get("risk_score", 0) >= 85
                                        or (v.get("risk_score", 0) >= 75 and _mb2 >= 5)
                                        or v.get("file_sensitivity") == "high"):
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
                                    if v.get("risk_score", 0) >= 85:
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
        # ---- 说明后校验(2026-08-21 AI准确性): 数字与窗口实际比对,不匹配自动修正 ----
        try:
            if isinstance(v, dict) and v.get("explanation"):
                import re as _re_v
                _expl = v["explanation"]
                # 域名计数校验: 提取说明中"域名×N次"模式,与窗口实际count比对
                _win_cnt = defaultdict(int)
                for e in w:
                    if e.category == "WEB":
                        d = ((e.raw or {}).get("domain") or "").lower()
                        if d:
                            root = ".".join(d.split(".")[-2:])  # 取根域名(含子域)
                            _win_cnt[root] += (e.count or 1)
                            _win_cnt[d] += (e.count or 1)
                for m in _re_v.finditer(r"([a-zA-Z0-9.-]+\.[a-z]{2,6})×(\d+)次", _expl):
                    dom, claimed = m.group(1).lower(), int(m.group(2))
                    actual = _win_cnt.get(dom, _win_cnt.get(".".join(dom.split(".")[-2:]), 0))
                    if actual and claimed != actual:
                        _expl = _expl.replace(f"{m.group(1)}×{claimed}次", f"{m.group(1)}×{actual}次")
                # "N次"泛指校验(无域名前缀): 取窗口WEB总数
                for m in _re_v.finditer(r"(?<![×\d])(\d+)次(?!.*(?:累计|今日))", _expl):
                    claimed = int(m.group(1))
                    tot = sum(e.count or 1 for e in w if e.category == "WEB")
                    if tot and claimed > tot * 1.5:  # 明显超出总量→修正
                        pass  # 可能含DOC计数,不强行修正,仅域名级修正
                v["explanation"] = _expl
        except Exception:
            pass
        # ---- 锚点接管: 访问即违规类(policy/data)分数统一按客观特征计算 ----
        # 同样的问题必须同分(2026-08-19用户要求);LLM分<30视为遥测等例外,不接管
        _anchored = None
        if isinstance(v, dict) and (v.get("risk_score") or 0) >= 30:
            _a = detector.anchor_score(v.get("intent"), w, day_total=_day_tot)
            if _a is None and v.get("intent") == "data_exfiltration":
                # 白名单目的地全掩护(2026-08-26何晴案例): 锚点证据门正确排除了公司通道
                # 上传,但LLM仍自行判85分外发——锚点None时LLM分无压制。窗口所有DOC上传
                # 目的地均白名单(含邻近推断) → 强制normal_work
                _webs_in_w = [(_tw, ((_tr or {}).get("domain") or "").lower())
                              for _te in w if _te.category == "WEB"
                              for _tw in [getattr(_te, "occurred_at", None)]
                              for _tr in [(_te.raw or {}).get("domain") and _te.raw]]
                _webs_in_w = [(t, d) for t, d in _webs_in_w if t and d]
                _sends_w = [e for e in w if e.category == "DOC" and e.action in ("SEND", "UPLOAD")]
                if _sends_w and all(dicts.whitelisted_dest(e.raw or {}, _webs_in_w, e.occurred_at) for e in _sends_w):
                    v = {**v, "intent": "normal_work", "risk_score": min(v.get("risk_score") or 0, 20),
                         "explanation": "[公司通道] " + (v.get("explanation") or "")}
            if _a is not None:
                v = {**v, "risk_score": _a}
                _anchored = _a
                # 文件内容敏感性修正(2026-08-26用户要求: 外发判断不能只看大小个数,
                # 要结合文件名上下文): AI定性file_sensitivity,程序按档加分——
                # 发1份试验方案与发1张私人照片不再同分
                _fs = str(v.get("file_sensitivity") or "").lower()
                if v.get("intent") == "data_exfiltration" and _fs in ("high", "mid"):
                    v = {**v, "risk_score": min(_a + (10 if _fs == "high" else 5), 95)}
        # ---- 招聘锚点: 程序化定分,AI只负责行为描述 ----
        # 重点站(BOSS/猎聘/51job/智联sndhr)——第一优先级场景(2026-08-20口径:
        # 求职分数必须≥邮箱/外发同档——单次65曾低于邮箱单次75,倒挂修正):
        #   单次(1-2次)=75(平邮箱单次); 反复3-9次=85; 高频≥10次=90(高于外发85);
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
                # 接管看窗口自身计数(含招聘域名才判job);定档用当日累计(高聪案例:
                # 分散多窗口不降档)。万亮案例: 纯AI窗口被当日累计拔成job80,说明全是
                # AI域名与场景矛盾(2026-08-20)——窗口无招聘域名的不判求职。
                _mj_lvl = max(_mj, _day_mj)
                _gn_lvl = max(_gn, _day_gn)
                if _mj >= 1:
                    if _mj_lvl >= 10:
                        _js = 90
                    elif _mj_lvl >= 3:
                        _js = 85
                    else:
                        _js = 75
                    v = {**v, "intent": "job_seeking",
                         "risk_score": min(_js + (5 if _off else 0) + (5 if _xd else 0), 95)}
                    _anchored = v["risk_score"]  # 客观计数定分,复核不推翻(见下)
                elif _gn >= 3 or (_gn >= 1 and _xd):
                    _js = 60 if _gn_lvl >= 10 else 55
                    v = {**v, "intent": "job_seeking",
                         "risk_score": min(_js + (5 if _off else 0) + (5 if _xd else 0), 65)}
                    _anchored = v["risk_score"]
                elif v.get("intent") == "job_seeking":
                    # 窗口内无任何招聘域名 → job_seeking结论无证据支撑,无条件压回。
                    # 行为史跨天标记+重度AI窗口曾让AI把纯AI使用误判成求职(2026-08-20
                    # 重判发现: 万亮AI助手221次被判job 70)——求职结论必须由当前窗口
                    # 的招聘访问支撑,历史标记只能加档不能独立成立
                    v = {**v, "intent": "baseline_deviation",
                         "risk_score": min(v.get("risk_score") or 30, 45)}
        # 豁免场景的研判加显式标注: 豁免人员(如HR)的研判照常落库但告警被拦,
        # 研判页/AI问答看到时必须能认出"这是已豁免的岗位行为"(2026-08-20展佳案例)
        try:
            if isinstance(v, dict) and exs and any(e.signal_type == v.get("intent") for e in exs):
                _exr = next(e.reason for e in exs if e.signal_type == v.get("intent"))
                v = {**v, "explanation": f"[已豁免:{_exr or '岗位需要'}] " + (v.get("explanation") or "")}
        except Exception:
            pass
        # ---- 锚点场景说明一致性: 锚点强制intent时,AI说明可能以窗口主信号(如AI)
        # 为主而只字不提触发域名(鄢荣梅案例: job告警说明全是doubao,招聘2次没写,
        # 2026-08-20)——说明不含触发域名的,前置事实摘要
        try:
            _SCEN_KW = {"job_seeking": ("招聘",),
                        "policy_violation": ("网盘", "邮箱"),
                        "data_exfiltration": ("文件助手", "网盘", "邮箱", "文件传输")}
            if isinstance(v, dict) and v.get("intent") in _SCEN_KW:
                _kw = _SCEN_KW[v["intent"]]
                _fd = defaultdict(int)
                for e in w:
                    if e.category != "WEB":
                        continue
                    d = ((e.raw or {}).get("domain") or "").lower()
                    rc = dicts.risk_class(d)
                    if rc and any(k in rc for k in _kw):
                        _fd[f"{rc}|{d}"] += (e.count or 1)
                if _fd:
                    _expl = v.get("explanation") or ""
                    _hit = False
                    for key in _fd:
                        d = key.split("|", 1)[1]
                        if d in _expl or ".".join(d.split(".")[-2:]) in _expl:
                            _hit = True
                            break
                    if not _hit:
                        _facts = "、".join(f"{k.split('|')[0]}({k.split('|')[1]})×{n}次"
                                           for k, n in sorted(_fd.items(), key=lambda x: -x[1])[:3])
                        v = {**v, "explanation": f"访问{_facts}。原始说明: " + _expl}
        except Exception:
            pass
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
                elif _anchored is not None:
                    pass  # 锚点场景(访问即违规类/招聘档位)分数由客观计数决定,
                    # 复核低分不推翻——单次访问BOSS必须65告警是用户口径,证据是
                    # 计数不是AI观点;复核降级只作用于AI自由判分的场景
                else:  # 分歧 → 降级到复核分(证据已被复核否定)
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
            _wm_final = max_id
            if _held_min_id:
                _wm_final = min(max_id, _held_min_id - 1)  # 扣留窗口的事件不入水位,下轮重建重判
            wm_row = ws.query(SettingRow).filter_by(key="last_judged_event_id").first()
            if wm_row:
                wm_row.value = str(_wm_final)
            else:
                ws.add(SettingRow(key="last_judged_event_id", value=str(_wm_final)))
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
            _detect_status.update(running=True, total=0, done=0, judged=0, alerts=0, error=None, phase="读取数据")

            def _prog(kind, val):
                _detect_status["total" if kind == "total" else "done"] = val

            judged, alerts = run_detection(risk_threshold, on_progress=_prog)
            _detect_status.update(running=False, judged=judged, alerts=alerts, phase=None,
                                  last_finished=bj_now().isoformat(),  # 北京时间,前端直接显示(旧utcnow差8h)
                                  last_judged=judged, last_alerts=alerts)
        except Exception as e:
            _detect_status.update(running=False, error=str(e), phase=None)
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
