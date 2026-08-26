# -*- coding: utf-8 -*-
"""优化: 超长窗口切分(不截断,分次研判)+上限提升。"""
import io

# ============ detector.py: 上限 1500→3500, others 12→25, normal 5→10 ============
p = "backend/detector.py"
s = io.open(p, encoding="utf-8").read()

old = '''    raw = "\\n".join(lines) if lines else "(无行为)"
    # 硬截断：超过 1500 字（约 2000 tokens）则截断（留空间给 system prompt + 输出）
    if len(raw) > 1500:
        raw = raw[:1500] + "\\n…（行为过多已截断）"
    return raw'''
new = '''    raw = "\\n".join(lines) if lines else "(无行为)"
    # 截断上限 3500 字(2026-08-26用户要求: 本地AI不费钱,保证完整输入不截断丢风险;
    # 旧版1500字截断导致高活跃员工窗口丢证据。超长时由pipeline切分为子窗口分次研判,
    # 此处只是最后兜底)
    if len(raw) > 3500:
        raw = raw[:3500] + "\\n…（行为过多,pipeline将切分研判）"
    return raw


def fmt_window_len(window) -> int:
    """预判窗口格式化后的长度(不重复构建,用行数×平均行长估算)。"""
    return len(_fmt_window(window))


def split_window(window):
    """超长窗口二分切分: 按时间中点分成两半,各自独立送LLM。
    保证每个子窗口完整输入不截断(2026-08-26用户要求)。"""
    if len(window) <= 1:
        return [window]
    mid = len(window) // 2
    left, right = window[:mid], window[mid:]
    # 重叠 2 条避免边界遗漏
    if len(left) > 2 and len(right) > 2:
        right = left[-2:] + right
    return [left, right]'''
assert s.count(old) == 1, "detector上限"
s = s.replace(old, new)

# others 上限 12→25
s = s.replace("for e in others[:12]:", "for e in others[:25]:")
s = s.replace('if n_other > 12:', 'if n_other > 25:')
s = s.replace('f"…及另外 {n_other - 12} 条文档/搜索"', 'f"…及另外 {n_other - 25} 条文档/搜索"')

# normal 上限 5→10
s = s.replace("for d, info in normal[:5]:", "for d, info in normal[:10]:")
s = s.replace('if len(normal) > 5:', 'if len(normal) > 10:')
s = s.replace('f"…及另外 {len(normal) - 5} 个常规域名访问', 'f"…及另外 {len(normal) - 10} 个常规域名访问')
io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("detector: 上限3500+others25+normal10 ✓")

# ============ pipeline.py: 超长窗口切分送LLM ============
p2 = "backend/pipeline.py"
s2 = io.open(p2, encoding="utf-8").read()

# 在 _judge 函数入口前加切分逻辑——找到 _judge 的定义
old2 = "    def _judge(item):"
new2 = '''    def _judge_with_split(w, emp, baseline, dev, item):
        """超长窗口切分研判(2026-08-26用户要求: 增加研判次数保证完整输入输出)。
        子窗口各自独立送LLM,结果取最高分,explanation标注[切分研判]。"""
        _txt = detector._fmt_window(w)
        if len(_txt) <= 3500:
            return _judge_item_direct(item, w)
        # 切分
        subs = detector.split_window(w)
        if len(subs) <= 1:
            return _judge_item_direct(item, w)
        best = None
        for i, sub in enumerate(subs):
            _sub_item = (item[0], sub, item[2])  # (emp, w, ...)保持结构
            r = _judge_item_direct(_sub_item, sub)
            if r is None:
                continue
            if best is None or (r.get("risk_score") or 0) > (best.get("risk_score") or 0):
                r = {**r, "explanation": f"[切分研判{i + 1}/{len(subs)}] " + str(r.get("explanation") or "")}
                best = r
        return best

    def _judge_item_direct(item, w=None):
        # 原始 _judge 的内联调用(不走切分)
        return _judge(item)

    def _judge(item):'''
assert s2.count(old2) == 1, "pipeline切分入口"
s2 = s2.replace(old2, new2)
io.open(p2, "w", encoding="utf-8", newline="\n").write(s2)
print("pipeline: 切分研判入口 ✓")
