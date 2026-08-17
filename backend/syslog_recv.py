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
                        s.add(RawLogRow(log_type=_lt, user=_u, app=_a, msg=msg[:1000]))
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


def _flush_loop():
    """每30秒刷新一次事件缓冲（收到 syslog 后近实时入库+研判）。每小时清理一次过期事件。"""
    print("[flush-loop] 启动", flush=True)
    global _flush_timer, _flush_count
    _flush_events()
    _flush_count += 1
    if _flush_count % 120 == 0:  # 约1小时维护一次
        try:
            import pipeline, dicts
            pipeline.cleanup_old_events(int(dicts.get_setting("retention_days", "90")))
            pipeline.cleanup_old_raw_logs(int(dicts.get_setting("raw_logs_retention_days", "7")))
            pipeline.auto_close_alerts()
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
            _state["count"] += 1
            with _lock:
                _state["recent"].append({
                    "t": datetime.datetime.now().strftime("%H:%M:%S"),
                    "from": addr[0],
                    "msg": text[:500],
                })
                _state["recent"] = _state["recent"][-500:]
            # 实时解析为标准事件
            try:
                from parser_sangfor import parse_sangfor_syslog
                ev = parse_sangfor_syslog(text)
                if ev:
                    with _buf_lock:
                        _event_buffer.append(ev)
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
        return {
            "enabled": _state["enabled"],
            "host": _state["host"],
            "port": _state["port"],
            "count": _state["count"],
            "ingested": _state.get("ingested", 0),
            "error": _state.get("error"),
            "recent": list(_state["recent"][-5:]),
        }
