"""UDP Syslog 接收器 + 实时解析入库研判管线。

接收深信服/IP-Guard syslog → 解析成标准事件 → 缓冲 → 每30秒批量降噪聚合入库 → 增量研判。
"""
import datetime
import socket
import threading

_state = {
    "enabled": False, "host": None, "port": None,
    "count": 0, "recent": [], "error": None,
    "thread": None, "sock": None, "ingested": 0,
    "last_recv": None,  # 最近一次收到报文的时间(datetime)——数据流心跳
}
_lock = threading.Lock()
_event_buffer = []
_buf_lock = threading.Lock()
_flush_timer = None
_last_profiles_ts = 0.0
_flush_count = 0


def _flush_events():
    """把缓冲的事件聚合入库 + 建画像 + 触发增量研判。原始报文也持久化。"""
    global _event_buffer
    # 取走缓冲与清空必须同一临界区,否则此间 _listen 新 append 的事件会被清空丢失
    with _buf_lock:
        events = _event_buffer[:]
        del _event_buffer[:]
    # 原始报文持久化 — 直接从_state["recent"]取(recvfrom后第一件事就存,100%有数据)
    import re as _re_mod
    try:
        from db import Session, RawLogRow, write_lock
        with _lock:
            recents = list(_state.get("recent", []))
            _state["recent"] = []  # 取走清空(避免重复insert),与_listen的append同锁互斥
        if recents:
            with write_lock:  # 与研判 _flush 串行写，避免写锁互等
                s = Session()
                try:
                    try:  # 原始日志用户列走别名转换(2026-08-20反馈: 已映射账号仍显示拼音)
                        import json as _js2
                        import dicts as _dc2
                        _al = _js2.loads(_dc2.get_setting("employee_alias") or "{}")
                    except Exception:
                        _al = {}
                    for m in recents:
                        msg = m.get("msg", "")
                        _lt = _u = _a = ""
                        _m1 = _re_mod.search(r"\[log_type:([^\]]+)\]", msg)
                        if _m1: _lt = _m1.group(1).strip()
                        _m2 = _re_mod.search(r"\[user:([^\]]+)\]", msg)
                        if _m2: _u = _m2.group(1).strip()
                        _m3 = _re_mod.search(r"\[app:([^\]]+)\]", msg)
                        if _m3: _a = _m3.group(1).strip()
                        if not _u:  # IPG报文: 解析线程已回填的lt/u/a优先于空regex
                            _lt = m.get("lt") or _lt
                            _u = m.get("u") or _u
                            _a = m.get("a") or _a
                        if _u in _al:  # 账号→中文名,与events同口径
                            _u = _al[_u]
                        s.add(RawLogRow(log_type=_lt, user=_u, app=_a, msg=msg[:4000]))
                    s.commit()
                    print(f"[raw] insert from recent {len(recents)}条", flush=True)
                finally:
                    s.close()
    except Exception as _re:
        print(f"[raw] insert失败: {_re}", flush=True)
    if not events:
        return
    try:
        import pipeline
        n = pipeline.ingest_events(events)
        with _lock:
            _state["ingested"] = _state.get("ingested", 0) + n
        if n > 0:
            # 画像节流(2026-08-24): 曾每30秒批后全量重建(1.5M事件+持写锁,锁竞争最大源)
            # 改为≥10分钟才重建;画像消费方(研判基线/画像页)容忍10分钟滞后
            import time as _pt
            global _last_profiles_ts
            if _pt.time() - _last_profiles_ts > 600:
                _last_profiles_ts = _pt.time()
                pipeline.profiles.build_profiles()
            pipeline.start_detection()
    except Exception as e:
        with _lock:
            _state["error"] = f"入库失败: {e}"


def _maybe_auto_scan():
    """每7天自动跑一次 AI 开集扫描(发现新的风险/摸鱼域名可能性)。
    结果只存建议+webhook提醒,永不自动写字典——人工采纳才生效。"""
    import dicts
    from datetime import timedelta
    from db import bj_now
    last = dicts.get_setting("auto_rules_last_run") or ""
    try:
        from datetime import datetime
        last_dt = datetime.fromisoformat(last)
    except Exception:
        last_dt = None
    if last_dt and bj_now() - last_dt < timedelta(days=7):
        return

    def _run():
        try:
            from api import auto_rules_scan
            auto_rules_scan()
        except Exception as e:
            print(f"[auto-scan] 触发失败: {e}", flush=True)
    threading.Thread(target=_run, daemon=True).start()


def _health_watchdog():
    """主动告警(每小时维护时检查,每项每天最多推1次):
    1) 数据流静默: 工作时间2小时无任何报文(深信服断推/网络变更——系统最大静默风险)
    2) 研判兜底率: 最近100条研判中规则兜底占比>50%(LLM网关故障,研判质量静默降级)
    3) 磁盘: 数据盘用量>80%
    """
    import json as _json
    import os
    import urllib.request as _ur
    from dicts import get_setting as dicts_get, set_setting as dicts_set

    def _notify(msg):
        url = dicts_get("notify_webhook", "")
        if not url:
            return
        try:
            body = _json.dumps({"msgtype": "text", "text": {"content": "⚠️ " + msg}}).encode("utf-8")
            _ur.urlopen(_ur.Request(url, data=body, headers={"Content-Type": "application/json"}), timeout=5)
        except Exception:
            pass

    def _once_per_day(key):
        today = datetime.datetime.now().strftime("%Y%m%d")
        if dicts_get("hw_" + key, "") == today:
            return False
        dicts_set("hw_" + key, today)
        return True

    # 1) 数据流心跳
    try:
        lr = _state.get("last_recv")
        hour = datetime.datetime.now().hour
        if lr and 9 <= hour < 20 and (datetime.datetime.now() - lr).total_seconds() > 7200:
            if _once_per_day("silent"):
                _notify(f"数据流静默: 工作时间已 {(datetime.datetime.now()-lr).total_seconds()/3600:.0f} 小时未收到深信服报文(最后 {lr.strftime('%H:%M')}),请检查推送/网络")
        if not lr and _state.get("enabled") and hour >= 11 and _once_per_day("silent"):
            _notify("数据流疑似中断: 服务运行中但启动后从未收到报文,请检查深信服推送配置")
    except Exception:
        pass
    # 1b) IPG(OTransLog)断流检测(2026-08-20接入): 工作时间2小时无IPG报文即提醒
    #     ——IPG推送独立于深信服,可能单边断;原始报文里含OTransLog即视为IPG在线
    try:
        from db import Session as _S2
        from db import RawLogRow as _RL2, bj_now as _bj2
        _hour = datetime.datetime.now().hour
        if 9 <= _hour < 20:
            _ss = _S2()
            try:
                _last_ipg = _ss.query(_RL2.received_at).filter(
                    _RL2.msg.like("%OTransLog%")).order_by(_RL2.id.desc()).first()
                if _last_ipg and _last_ipg[0]:
                    _silent = (_bj2() - _last_ipg[0]).total_seconds()
                    if _silent > 7200 and _once_per_day("ipg_silent"):
                        _notify(f"IPG日志断流: 工作时间已{_silent/3600:.0f}小时未收到IP-Guard报文(最后{_last_ipg[0].strftime('%H:%M')}),请检查IPG外发配置")
            finally:
                _ss.close()
    except Exception:
        pass
    # 2) 研判兜底率
    try:
        from db import Session
        from db import VerdictRow
        ss = Session()
        try:
            recent = ss.query(VerdictRow).order_by(VerdictRow.id.desc()).limit(100).all()
            if len(recent) >= 20:
                fb = sum(1 for v in recent if not v.ai_participated)
                if fb / len(recent) > 0.5 and _once_per_day("fallback"):
                    _notify(f"研判质量降级: 最近{len(recent)}条研判中 {fb} 条为规则兜底(LLM不可达?),请检查模型网关 {dicts_get('llm_base_url') or '10.4.128.18:4000'}")
        finally:
            ss.close()
    except Exception:
        pass
    # 3) 磁盘
    try:
        import shutil
        import db as _db
        du = shutil.disk_usage(os.path.dirname(_db.DB_PATH) or "/")
        pct = (du.total - du.free) / du.total * 100
        if pct > 80 and _once_per_day("disk"):
            _notify(f"磁盘告警: 数据盘已用 {pct:.0f}%(剩余 {du.free/2**30:.0f}G),请清理或扩容(备份目录/旧数据)")
    except Exception:
        pass


_MAINT_RUNNING = set()
_MAINT_LOCK = threading.Lock()


def _bg_maint(fn, name):
    """维护任务后台线程化(2026-08-26): 周级LLM任务(storyline多次长调用/docscan/
    weekly/dayreview)与selfheal巡检原先内联在唯一的30s flush线程里——一轮跑几
    分钟到数小时,期间事件入库完全停摆,UDP缓冲溢出丢包(08-21已发生一次)。
    移入daemon线程,并加"上一轮未跑完则跳过"守卫防重叠。"""
    with _MAINT_LOCK:
        if name in _MAINT_RUNNING:
            print(f"[maint] {name}上一轮仍在运行,本轮跳过", flush=True)
            return
        _MAINT_RUNNING.add(name)

    def _wrap():
        try:
            fn()
        except Exception as e:
            print(f"[maint] {name}失败: {e}", flush=True)
        finally:
            with _MAINT_LOCK:
                _MAINT_RUNNING.discard(name)
    threading.Thread(target=_wrap, daemon=True).start()


def _maint_10min():
    """10分钟巡检(后台线程): patterns/massops/晚到关联/selfheal。"""
    try:  # 行为模式(10分钟): 压缩外发/改名掩盖/环比突增(2026-08-21)
        from patterns import run_all_patterns
        _pat = run_all_patterns()
        if any(_pat.values()):
            print(f"[patterns] {_pat}", flush=True)
    except Exception as _pe:
        print(f"[patterns] 失败: {_pe}", flush=True)
    try:  # 行为聚合(10分钟): 大量删除=离职前兆,实时化(2026-08-21用户要求)
        from massops import scan_mass_deletes
        _md = scan_mass_deletes()
        if _md.get("created"):
            print(f"[massops] 新增聚合告警{_md['created']}条", flush=True)
    except Exception as _me:
        print(f"[massops] 失败: {_me}", flush=True)
    try:  # 晚到证据关联(2026-08-26): 深信服延迟>12分钟等待窗的兜底
        from massops import reconcile_late_evidence
        _rl = reconcile_late_evidence()
        if _rl.get("closed") or _rl.get("enriched"):
            print(f"[late-evidence] 关闭误报{_rl['closed']}条/回填去向{_rl['enriched']}条", flush=True)
    except Exception as _le:
        print(f"[late-evidence] 失败: {_le}", flush=True)
    try:
        from selfheal import selfcheck
        _r = selfcheck()
        if _r.get("fixes"):
            print(f"[selfheal] 修复 {len(_r['fixes'])} 项: " + "; ".join(_r["fixes"][:6]), flush=True)
        if _r.get("error"):
            print(f"[selfheal] 失败: {_r['error']}", flush=True)
    except Exception as _se:
        print(f"[selfheal] 失败: {_se}", flush=True)


def _maint_hourly():
    """小时维护(后台线程): 清理/扫描/看门狗/周级任务 + 风险记忆重建。"""
    try:
        import pipeline, dicts
        pipeline.cleanup_old_events(int(dicts.get_setting("retention_days", "90")))
        pipeline.cleanup_old_raw_logs(int(dicts.get_setting("raw_logs_retention_days", "7")))
        pipeline.auto_close_alerts()
        _maybe_auto_scan()  # 每周自动开集扫描(到期才真正跑)
        _health_watchdog()  # 数据流静默/兜底率/磁盘 主动告警(每项每天最多1次)
        try:
            from api import _alias_discover
            _alias_discover()  # 用户名映射自动发现(拼音级自动,推测级进候选)
        except Exception:
            pass
        try:
            from deepaudit import run_deep_audit
            _da = run_deep_audit()
            _bad = {k: v for k, v in _da.items() if k.startswith("D") and isinstance(v, int) and v not in (0,)}
            if _bad:
                print(f"[deepaudit] 异常项: {_bad}", flush=True)
        except Exception as _de:
            print(f"[deepaudit] 失败: {_de}", flush=True)
        try:  # 风险行为记忆小时重建(2026-08-26接线): commit 6f8927c宣称的"小时重建"
            # 原先update_memory全仓零调用,表数据只靠手跑脚本,现在真正接入
            from riskmemory import update_memory
            _n = update_memory()
            print(f"[riskmemory] 小时重建 {_n} 条档案", flush=True)
        except Exception as _rme:
            print(f"[riskmemory] 失败: {_rme}", flush=True)
        try:  # 周报(每周五17点,R1): 风险综述+webhook(2026-08-21)
            from db import bj_now as _bj9
            _now9 = _bj9()
            if _now9.weekday() == 4 and _now9.hour >= 17 and \
                    dicts.get_setting("weekly_last", "") != _now9.strftime("%Y%m%d"):
                dicts.set_setting("weekly_last", _now9.strftime("%Y%m%d"))
                from weekly import gen_weekly
                _wk = gen_weekly()
                print(f"[weekly] 周报: {_wk.get('headline', '')[:40]}", flush=True)
        except Exception as _we:
            print(f"[weekly] 失败: {_we}", flush=True)
        try:  # N+1日复核(每天凌晨,回看昨天全天): 修正实时结论(2026-08-21)
            from db import bj_now as _bj8
            _d8 = _bj8()
            if _d8.hour >= 1 and dicts.get_setting("day_review_last", "") != _d8.strftime("%Y%m%d"):
                dicts.set_setting("day_review_last", _d8.strftime("%Y%m%d"))
                from dayreview import run_day_review
                _r8 = run_day_review()
                print(f"[dayreview] N+1完成(回看{_r8.get('day')}): 候选{_r8.get('candidates')} "
                      f"升{_r8.get('upgraded')}降{_r8.get('downgraded')}", flush=True)
        except Exception as _de8:
            print(f"[dayreview] 失败: {_de8}", flush=True)
        try:  # 风险故事线(每周,R1): 离职信号串成时间叙事(2026-08-21)
            from datetime import timedelta as _td7
            from db import bj_now as _bj7
            _last7 = dicts.get_setting("risk_story_last", "")
            _today7 = _bj7().strftime("%Y%m%d")
            if _last7 != _today7 and (_last7 == "" or
                    _bj7() - datetime.datetime.strptime(_last7, "%Y%m%d") >= _td7(days=7)):
                dicts.set_setting("risk_story_last", _today7)
                from storyline import build_stories
                _r7 = build_stories()
                print(f"[storyline] 周更完成: {_r7.get('stories')}条", flush=True)
        except Exception as _se7:
            print(f"[storyline] 失败: {_se7}", flush=True)
        try:  # IPG文档AI深扫(每周,R1): 外发模式/敏感文件特征/建议(2026-08-20)
            from datetime import timedelta as _td6
            from db import bj_now as _bj6
            _last = dicts.get_setting("ipg_doc_scan_last", "")
            _today = _bj6().strftime("%Y%m%d")
            if _last != _today and (_last == "" or
                    _bj6() - datetime.datetime.strptime(_last, "%Y%m%d") >= _td6(days=7)):
                dicts.set_setting("ipg_doc_scan_last", _today)
                from docscan import run_doc_scan
                _r6 = run_doc_scan()
                print(f"[docscan] 周扫完成: findings={len(_r6.get('findings', []))}", flush=True)
        except Exception as _dse:
            print(f"[docscan] 失败: {_dse}", flush=True)
    except Exception:
        pass


def _flush_loop():
    """每30秒刷新一次事件缓冲（收到 syslog 后近实时入库+研判）。每小时清理一次过期事件。"""
    print("[flush-loop] 启动", flush=True)
    global _flush_timer, _flush_count
    _flush_events()
    _flush_count += 1
    # 不变量自检自愈: 每10分钟独立跑一次(20×30s),不等小时级维护——
    # 用户要求循环检测加密(2026-08-20),纯程序检查零LLM成本
    # 研判水位保底(2026-08-31~09-01连续两天D4>1300): 检测线程可能异常退出
    # 且无人重拉——每10分钟检查水位,超过500条未判事件自动拉起研判
    if _flush_count % 20 == 0:
        try:
            _wm = int(dicts.get_setting("last_judged_event_id", "0") or "0")
            import db as _db
            _ms = Session().query(_db.EventRow.id).order_by(_db.EventRow.id.desc()).first()
            if _ms and _ms[0] - _wm > 500:
                import pipeline
                pipeline.start_detection()
                print(f"[watchdog] 水位差{_ms[0] - _wm}>500,自动拉起研判", flush=True)
        except Exception as _we:
            print(f"[watchdog] 水位检查失败: {_we}", flush=True)
    if _flush_count % 20 == 0:
        _bg_maint(_maint_10min, "10min")
    if _flush_count % 120 == 0:  # 约1小时维护一次
        _bg_maint(_maint_hourly, "hourly")
    if _state["enabled"]:
        _flush_timer = threading.Timer(30.0, _flush_loop)
        _flush_timer.daemon = True
        _flush_timer.start()


def _listen(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # 接收缓冲扩容(2026-08-21实测内核丢包4700个): 深信服/IPG按批次突发推送,
    # 瞬时数百条超过默认208KB缓冲(~百个报文)即溢出丢弃。请求8MB,实际受
    # net.core.rmem_max封顶(compose已同步调大)。
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        _got = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        if _got < 2 * 1024 * 1024:
            print(f"[listen] SO_RCVBUF仅 {_got // 1024}KB(rmem_max未放开),仍有突发丢包风险", flush=True)
    except OSError:
        pass
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # 允许rebind,避免旧socket泄漏时bind失败
    except (AttributeError, OSError):
        pass
    try:
        s.bind((host, int(port)))
    except Exception as e:
        with _lock:
            _state["error"] = f"绑定失败: {e}"
        return
    s.settimeout(2.0)
    with _lock:
        _state["sock"] = s
        _state["error"] = None
    while _state["enabled"]:
        try:
            data, addr = s.recvfrom(65535)
            text = data.decode("utf-8", "replace")
            with _lock:
                _state["count"] += 1
                _state["last_recv"] = datetime.datetime.now()
                _state["recent"].append({
                    "t": datetime.datetime.now().strftime("%H:%M:%S"),
                    "from": addr[0],
                    "msg": text[:4000],  # IPG JSON报文1-3KB,500截断丢掉文件名/动作/用户字段(2026-08-20)
                })
                _state["recent"] = _state["recent"][-5000:]  # 2026-08-25: 500上限在突发时丢原始报文(实测今日丢~1万条),raw_logs非全量
            # 实时解析为标准事件——按报文特征路由(2026-08-20修复:
            # 深信服解析器是宽松KV提取,对IPG报文也返回垃圾事件,IPG解析器从未被执行;
            # 必须先认OTransLog特征再落深信服)
            try:
                _is_ipg = "OTransLog" in text
                ev = None
                if _is_ipg:
                    from parser_ipg import parse_ipg_syslog
                    ev = parse_ipg_syslog(text)
                else:
                    from parser_sangfor import parse_sangfor_syslog
                    ev = parse_sangfor_syslog(text)
                if ev:
                    with _buf_lock:
                        _event_buffer.append(ev)
                    if _is_ipg:  # 原始日志页的用户/应用/类型列: IPG报文无[user:]标记,
                        with _lock:  # 用解析结果回填(2026-08-20用户反馈"没有用户和应用")
                            if _state["recent"]:
                                _state["recent"][-1]["lt"] = f"IPG-{ev.category.lower()}"
                                _state["recent"][-1]["u"] = ev.employee_id
                                _state["recent"][-1]["a"] = (ev.raw or {}).get("app") or (ev.raw or {}).get("title") or ""
            except Exception:
                pass
        except socket.timeout:
            continue
        except OSError as _oe:
            with _lock:
                _state["error"] = f"监听OSError(重试不退出): {_oe}"
            import time as _t; _t.sleep(1)
            continue
    try:
        s.close()
    except OSError:
        pass


def start(host, port):
    global _flush_timer
    stop()
    with _lock:
        _state.update(enabled=True, host=host, port=int(port), count=0, recent=[], error=None, ingested=0)
    t = threading.Thread(target=_listen, args=(host, int(port)), daemon=True)
    _state["thread"] = t
    t.start()
    print("[start] _listen线程已启动, 即将调_flush_loop", flush=True)
    _flush_loop()


def _watchdog():
    """每60s检查, syslog停了(syslog_enabled=1但enabled=False)自动重启, 防数据流断。"""
    import time as _t
    while True:
        _t.sleep(60)
        try:
            if not _state.get("enabled"):
                import dicts as _d
                if _d.get_setting("syslog_enabled", "0") == "1":
                    start(_state.get("host") or "0.0.0.0", _state.get("port") or 8514)
        except Exception:
            pass


def start_watchdog():
    threading.Thread(target=_watchdog, daemon=True).start()


def stop():
    global _flush_timer
    with _lock:
        _state["enabled"] = False
        sock = _state.get("sock")
        thr = _state.get("thread")
        _state["sock"] = None
    if _flush_timer:
        _flush_timer.cancel()
        _flush_timer = None
    if sock:
        try: sock.close()
        except OSError: pass
    if thr:  # 等_listen线程退出(确保socket释放), 避免重启bind失败
        try: thr.join(timeout=3)
        except Exception: pass
        with _lock:
            _state["thread"] = None
    th = _state.get("thread")
    if th and th.is_alive():
        th.join(timeout=3)


def status():
    with _lock:
        lr = _state.get("last_recv")
        return {
            "enabled": _state["enabled"],
            "host": _state["host"],
            "port": _state["port"],
            "count": _state["count"],
            "ingested": _state.get("ingested", 0),
            "error": _state.get("error"),
            "recent": list(_state["recent"][-5:]),
            "last_recv": lr.strftime("%Y-%m-%d %H:%M:%S") if lr else None,
        }
