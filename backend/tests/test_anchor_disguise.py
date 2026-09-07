# -*- coding: utf-8 -*-
"""外发伪装信号(2026-09-07用户逆向思考): 锚点对『改名遮蔽』『压缩打包』两条
伪装链加分。RENAME在SEND前≤30分钟→floor+5(与has_write同名链互补,不要求同名);
压缩包外发→floor+5且不吃_AUTO_NAME默认名降档(打包本身即刻意动作)。"""
from datetime import datetime
from types import SimpleNamespace


def _ev(cat, act, tv, ts, raw=None):
    return SimpleNamespace(category=cat, action=act, target_value=tv,
                           occurred_at=ts, raw=raw if raw is not None else {},
                           count=1, size_bytes=1048576)  # 1MB:避开0字节空文件封顶75


_T0 = datetime(2026, 9, 7, 10, 0)
_RAW = {"channel": "weixin", "dest_path": "https://filehelper.weixin.qq.com/x"}


def test_baseline_send_weixin_80():
    """基线: 单发普通文档走微信通道=80档,无伪装信号不加分。"""
    import detector
    w = [_ev("DOC", "SEND", "周报.docx", _T0, _RAW)]
    assert detector.anchor_score("data_exfiltration", w) == 80


def test_rename_before_send_adds_5():
    """外发前20分钟有RENAME→+5(改名遮蔽链,80→85)。"""
    import detector
    w = [_ev("DOC", "RENAME", "notes.docx", datetime(2026, 9, 7, 9, 40)),
         _ev("DOC", "SEND", "notes.docx", _T0, _RAW)]
    # RENAME同名先写后发本就吃has_write+10(70+10=80),伪装链再+5→85
    assert detector.anchor_score("data_exfiltration", w) == 85


def test_archive_send_no_auto_name_discount():
    """压缩包外发: 字面含'新建'(默认名词典)也不吃75降档,且+5→85。"""
    import detector
    w = [_ev("DOC", "SEND", "新建压缩包.zip", _T0, _RAW)]
    assert detector.anchor_score("data_exfiltration", w) == 85


def test_rename_after_send_no_bonus():
    """RENAME发生在外发之后(乱序/事后整理)→不加分,维持80。"""
    import detector
    w = [_ev("DOC", "SEND", "notes.docx", datetime(2026, 9, 7, 9, 40), _RAW),
         _ev("DOC", "RENAME", "notes.docx", _T0)]
    assert detector.anchor_score("data_exfiltration", w) == 80
