# -*- coding: utf-8 -*-
import io
p = "backend/pipeline.py"
s = io.open(p, encoding="utf-8").read()

# 在 submit 处替换为切分版
old = "        futs = {pool.submit(_judge, item): i for i, item in enumerate(to_judge)}"
new = '''        def _judge_auto(item):
            """超长窗口自动切分(2026-08-26用户要求: 本地AI不费钱,增加研判次数
            保证完整输入输出不截断丢风险)。子窗口各自送LLM取最高分。"""
            emp, w, baseline, dev = item
            _txt = detector._fmt_window(w)
            if len(_txt) <= 3500:
                return _judge(item)
            subs = detector.split_window(w)
            if len(subs) <= 1:
                return _judge(item)
            best = None
            for i, sub in enumerate(subs):
                r = _judge((emp, sub, baseline, dev))
                if r is None:
                    continue
                if best is None or (r.get("risk_score") or 0) > (best.get("risk_score") or 0):
                    best = r
            if best and len(subs) > 1:
                best = {**best, "explanation": f"[切分研判/{len(subs)}段取最高] " + str(best.get("explanation") or "")}
            return best

        futs = {pool.submit(_judge_auto, item): i for i, item in enumerate(to_judge)}'''
assert s.count(old) == 1, "submit替换"
s = s.replace(old, new)
io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("pipeline切分研判 ✓")
