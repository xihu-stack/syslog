# -*- coding: utf-8 -*-
"""源头修复: N+0研判时自动注入深信服目的地推断(不等AI追问)。
这是最关键的一层——准确性高于及时性(用户口径2026-08-26)。"""
import io

p = "backend/detector.py"
s = io.open(p, encoding="utf-8").read()

# 在 analyze_window 构建user文本时,如果有空目的地SEND,自动查询深信服并注入
old = '''    user = (f"员工：{window[0].employee_id}（设备：{window[0].device_id}）\\n"
            f"行为序列：\\n{_fmt_window(window)}{g_txt}{profile_txt}{dev_txt}{exempt_txt}{hist_txt}{day_txt}\\n\\n"'''
new = '''    # 源头注入深信服目的地(2026-08-26用户要求: 准确性>及时性,不等AI追问——
    # 空目的地SEND时主动查深信服浏览数据,30分钟证据等待已保证数据到齐)
    _dest_hint = ""
    _unk_sends = [e for e in window if e.category == "DOC" and e.action in ("SEND", "UPLOAD")
                  and not dicts.dest_host(e.raw or {})]
    if _unk_sends:
        try:
            from db import Session as _S2, EventRow as _E2
            from datetime import timedelta as _td2
            _s2 = _S2()
            try:
                _webs2 = _s2.query(_E2).filter(
                    _E2.employee_id == window[0].employee_id,
                    _E2.category == "WEB",
                    _E2.occurred_at >= (_unk_sends[0].occurred_at - _td2(minutes=10)),
                    _E2.occurred_at <= (_unk_sends[-1].occurred_at + _td2(minutes=10))).all()
                _wdoms = {}
                for w2 in _webs2:
                    d = ((w2.raw or {}).get("domain") or "").lower()
                    if d and not d.startswith(("ws.", "statistic.", "tm.", "log.", "telemetry.")):
                        _wdoms[d] = _wdoms.get(d, 0) + 1
                if _wdoms:
                    _wl2 = [x.lower() for x in (dicts.get("risk_whitelist_domains") or [])]
                    _top3 = sorted(_wdoms, key=_wdoms.get, reverse=True)[:3]
                    _hints = []
                    for d in _top3:
                        if any(d == x or d.endswith("." + x) for x in _wl2):
                            _hints.append(f"{d}=公司白名单通道")
                        else:
                            _hints.append(d)
                    _dest_hint = f"\\n【深信服目的地推断】上传时刻±10分钟浏览: {', '.join(_hints)}\\n(据此判断文件去向;白名单通道=正常办公)"
            finally:
                _s2.close()
        except Exception:
            pass

    user = (f"员工：{window[0].employee_id}（设备：{window[0].employee_id}）\\n"
            f"行为序列：\\n{_fmt_window(window)}{_dest_hint}{g_txt}{profile_txt}{dev_txt}{exempt_txt}{hist_txt}{day_txt}\\n\\n"'''
assert s.count(old) == 1, "analyze注入"
s = s.replace(old, new)
io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("深信服目的地源头注入 ✓")
