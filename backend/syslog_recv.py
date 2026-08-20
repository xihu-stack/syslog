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


def _flush_loop():
    """每30秒刷新一次事件缓冲（收到 syslog 后近实时入库+研判）。每小时清理一次过期事件。"""
    print("[flush-loop] 启动", flush=True)
    global _flush_timer, _flush_count
    _flush_events()
    _flush_count += 1
    # 不变量自检自愈: 每10分钟独立跑一次(20×30s),不等小时级维护——
    # 用户要求循环检测加密(2026-08-20),纯程序检查零LLM成本
    if _flush_count % 20 == 0:
        try:
            from selfheal import selfcheck
            _r = selfcheck()
            if _r.get("fixes"):
                print(f"[selfheal] 修复 {len(_r['fixes'])} 项: " + "; ".join(_r["fixes"][:6]), flush=True)
            if _r.get("error"):
                print(f"[selfheal] 失败: {_r['error']}", flush=True)
        except Exception as _se:
            print(f"[selfheal] 失败: {_se}", flush=True)
    if _flush_count % 120 == 0:  # 约1小时维护一次
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
        except Exception:
            pass
    if _state["enabled"]:
        _flush_timer = threading.Timer(30.0, _flush_loop)
        _flush_timer.daemon = True
        _flush_timer.start()


def _listen(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
                _state["recent"] = _state["recent"][-500:]
            # 实时解析为标准事件
            try:
                from parser_sangfor import parse_sangfor_syslog
                ev = parse_sangfor_syslog(text)
                _is_ipg = False
                if ev is None:  # 深信服格式不匹配 → 试IP-Guard(OTransLog JSON)
                    from parser_ipg import parse_ipg_syslog
                    ev = parse_ipg_syslog(text)
                    _is_ipg = ev is not None
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
