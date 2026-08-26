# -*- coding: utf-8 -*-
import io

p = "backend/pipeline.py"
s = io.open(p, encoding="utf-8").read()

# 1) _expl_ok 改计分制(4/5即过)
old = '''                    def _expl_ok(emp, wstart, v, w):
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
                        return all([has_who, has_time, has_ch, has_obj, has_q])'''
new = '''                    def _expl_ok(emp, wstart, v, w):
                        """说明完整度自检(2026-08-26): 计分制,5项中≥4项即合格——
                        旧版all()过严(AI写'利用微信'无'通过'字样即被判缺,整条被模板
                        覆盖成'存在相关行为'的空洞句,houshunan案例)。"""
                        e = str(v.get("explanation") or "")
                        if len(e) < 25 or "系统按窗口事实生成" in e:
                            return False
                        sc = 0
                        if emp[:2] in e or "员工" in e:
                            sc += 1
                        _ds = str(wstart)[5:10]
                        if any(x in e for x in (_ds, "凌晨", "上午", "下午", "工作时段", "深夜", "夜间", "时段")):
                            sc += 1
                        if any(x in e for x in ("通过", "经", "exe", "通道", "利用", "使用")):
                            sc += 1
                        if ("『" in e) or ("×" in e) or ("." in e) or ("访问" in e):
                            sc += 1
                        if any(x in e for x in ("属", "风险", "嫌疑", "违规", "正常", "偏离")):
                            sc += 1
                        return sc >= 4'''
assert s.count(old) == 1, "ok改计分"
s = s.replace(old, new)

# 2) 覆盖改追加(保留AI语义,补程序事实)
old2 = '''                        if not _expl_ok(emp, wstart, v, w):
                            v["explanation"] = _factual_expl(emp, w, wstart, v)'''
new2 = '''                        if not _expl_ok(emp, wstart, v, w):
                            _orig = str(v.get("explanation") or "").strip()
                            _fact = _factual_expl(emp, w, wstart, v)
                            if len(_orig) >= 15 and "→→" not in _orig:
                                # AI说明有内容但缺要素→追加事实(不整体覆盖,保留语义判断)
                                v["explanation"] = _orig + " | 补充: " + _fact
                            else:
                                v["explanation"] = _fact'''
assert s.count(old2) == 1, "覆盖改追加"
s = s.replace(old2, new2)

# 3) fallback 列出真实事件(不要"存在相关行为"废话)
old3 = '''                        if _doms:
                            return f"{emp}在{_t}访问风险域名{'、'.join(_doms[:3])},属{_inten}(系统按窗口事实生成)。"
                        return f"{emp}在{_t}存在{_inten}相关行为(系统按窗口事实生成)。"'''
new3 = '''                        if _doms:
                            return f"{emp}在{_t}访问风险域名{'、'.join(_doms[:3])},属{_inten}(系统按窗口事实生成)。"
                        # 兜底也要具体: 列出窗口内各类行为统计,不写"存在相关行为"废话
                        from collections import Counter as _CC
                        _acts = _CC(f"{e.category}/{e.action}" for e in w if getattr(e, "category", ""))
                        _topdom = []
                        for e in w:
                            if e.category == "WEB":
                                _d = ((e.raw or {}).get("domain") or "")[:30]
                                if _d and _d not in _topdom:
                                    _topdom.append(_d)
                        _act_txt = "、".join(f"{k}×{n}" for k, n in _acts.most_common(4))
                        _dom_txt = (";域名: " + ", ".join(_topdom[:3])) if _topdom else ""
                        return f"{emp}在{_t}的行为: {_act_txt}{_dom_txt},属{_inten}(系统按窗口事实生成)。"'''
assert s.count(old3) == 1, "fallback具体化"
s = s.replace(old3, new3)

io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("自检降严+追加策略+fallback具体化 ✓")
