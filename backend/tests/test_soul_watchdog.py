# -*- coding: utf-8 -*-
"""生命体征(Task11): 研判看门狗——running且phase=LLM研判中且done停滞>stall
→dump栈+[soul-watchdog]日志;done推进自动复位;非running忽略。"""
import time


def test_watchdog_fires_on_stall(monkeypatch):
    import pipeline
    import faulthandler
    fired = []
    monkeypatch.setattr(pipeline, "detection_status",
                        lambda: {"running": True, "phase": "LLM研判中", "done": 7})
    monkeypatch.setattr(faulthandler, "dump_traceback", lambda: fired.append(1))
    pipeline.start_soul_watchdog(stall_seconds=0.3, poll_seconds=0.1)
    time.sleep(0.9)
    pipeline._SOUL_WD["stop"] = True
    assert fired, "停滞超时应dump栈并打[soul-watchdog]"


def test_watchdog_resets_on_progress(monkeypatch):
    import pipeline
    state = {"done": 1}
    import faulthandler
    fired = []
    monkeypatch.setattr(pipeline, "detection_status",
                        lambda: {"running": True, "phase": "LLM研判中", "done": state["done"]})
    monkeypatch.setattr(faulthandler, "dump_traceback", lambda: fired.append(1))
    pipeline.start_soul_watchdog(stall_seconds=0.4, poll_seconds=0.1)
    for _ in range(4):  # done持续推进,不触发
        time.sleep(0.15)
        state["done"] += 1
    time.sleep(0.15)
    pipeline._SOUL_WD["stop"] = True
    assert not fired


def test_watchdog_ignores_not_running(monkeypatch):
    import pipeline
    import faulthandler
    fired = []
    monkeypatch.setattr(pipeline, "detection_status",
                        lambda: {"running": False, "phase": None, "done": 0})
    monkeypatch.setattr(faulthandler, "dump_traceback", lambda: fired.append(1))
    pipeline.start_soul_watchdog(stall_seconds=0.3, poll_seconds=0.1)
    time.sleep(0.6)
    pipeline._SOUL_WD["stop"] = True
    assert not fired
