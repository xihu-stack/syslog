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


def _flush_events():
    """把缓冲的事件聚合入库 + 建画像 + 触发增量研判。"""
    global _event_buffer
    with _buf_lock:
        if not _event_buffer:
            return
        events = _event_buffer[:]
        _event_buffer = []
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
    """每30秒刷新一次事件缓冲（收到 syslog 后近实时入库+研判）。"""
    global _flush_timer
    _flush_events()
    if _state["enabled"]:
        _flush_timer = threading.Timer(30.0, _flush_loop)
        _flush_timer.daemon = True
        _flush_timer.start()


def _listen(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
                _state["recent"].append({
                    "t": datetime.datetime.now().strftime("%H:%M:%S"),
                    "from": addr[0],
                    "msg": text[:500],
                })
                _state["recent"] = _state["recent"][-50:]
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
        except OSError:
            break
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
    _flush_loop()


def stop():
    global _flush_timer
    with _lock:
        _state["enabled"] = False
        sock = _state.get("sock")
    if _flush_timer:
        _flush_timer.cancel()
        _flush_timer = None
    if sock:
        try:
            sock.close()
        except OSError:
            pass
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
