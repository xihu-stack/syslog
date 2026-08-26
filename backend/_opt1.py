# -*- coding: utf-8 -*-
"""优化1+2: 方向语义标记 + 说明完整度自检。"""
import io

# ============ detector.py: 方向标记 + 提示词规则 ============
p = "backend/detector.py"
s = io.open(p, encoding="utf-8").read()

# A1) DOC行加方向标记
old = '''            lines.append(f"{t} [{src}] [{e.action}] {e.target_value}{_sz}（通道={(e.raw or {}).get('channel')}, 应用={(e.raw or {}).get('app')}）{_dest}")'''
new = '''            # 方向标记(2026-08-26高聪案例: 说明把"下载缩略图"定性为外发对象——
            # 下载/接收是数据进入本机,方向为收,不是外发证据)
            _dir = "↑发" if e.action in ("SEND", "UPLOAD", "PRINT", "BURN") else ("↓收" if e.action in ("DOWNLOAD", "RECV") else "  ")
            lines.append(f"{t} [{src}] [{e.action}{_dir}] {e.target_value}{_sz}（通道={(e.raw or {}).get('channel')}, 应用={(e.raw or {}).get('app')}）{_dest}")'''
assert s.count(old) == 1, "A1"
s = s.replace(old, new)

# A2) 提示词方向铁律
old2 = "【通道具体性铁律】"
new2 = ("【方向铁律】行为序列中标注[↓收]的动作(下载/接收)是数据**进入**本机——严禁在explanation里把下载/接收的文件"
        "定性为外发对象或外发内容;外发只能引用[↑发](SEND/UPLOAD/PRINT/BURN)动作的文件;下载仅可作为行为上下文提及。\n"
        "【通道具体性铁律】")
assert s.count(old2) == 1, "A2"
s = s.replace(old2, new2, 1)
io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("A 方向语义 ✓")

# ============ pipeline.py: 说明完整度自检 ============
p2 = "backend/pipeline.py"
s2 = io.open(p2, encoding="utf-8").read()

old3 = '''                    import llm_client as _lc2
                    for emp, device, wstart, wend, hashes, v in buf:'''
new3 = '''                    import llm_client as _lc2

                    def _expl_ok(emp, wstart, v, w):
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
                        return all([has_who, has_time, has_ch, has_obj, has_q])

                    def _factual_expl(emp, w, wstart, v):
                        _sends = [e for e in w if e.category == "DOC" and e.action in ("SEND", "UPLOAD", "PRINT")]
                        _doms = []
                        for e in w:
                            if e.category == "WEB":
                                d = ((e.raw or {}).get("domain") or "").lower()
                                if d and dicts.risk_class(d) and d not in _doms:
                                    _doms.append(d)
                        _t = str(wstart)[5:16].replace("T", " ")
                        _inten = {"data_exfiltration": "数据外发", "policy_violation": "违规访问",
                                  "job_seeking": "求职信号", "baseline_deviation": "行为偏离",
                                  "normal_work": "正常办公"}.get(v.get("intent"), v.get("intent") or "行为")
                        if _sends:
                            _fs = "、".join(f"『{(e.target_value or '未命名')[:36]}』" for e in _sends[:3])
                            _mb = sum((e.size_bytes or 0) for e in _sends) / 1048576
                            _ch = (_sends[0].raw or {}).get("app") or (_sends[0].raw or {}).get("channel") or "网络"
                            return (f"{emp}在{_t}通过{_ch}发送{_fs}共{len(_sends)}个文件"
                                    + (f"({_mb:.1f}MB)" if _mb >= 0.5 else "")
                                    + f",属{_inten}(系统按窗口事实生成)。")
                        if _doms:
                            return f"{emp}在{_t}访问风险域名{'、'.join(_doms[:3])},属{_inten}(系统按窗口事实生成)。"
                        return f"{emp}在{_t}存在{_inten}相关行为(系统按窗口事实生成)。"

                    for emp, device, wstart, wend, hashes, v in buf:'''
assert s2.count(old3) == 1, "B1"
s2 = s2.replace(old3, new3)

old4 = '''                        if v.get("explanation"):
                            _e2 = _lc2.strip_think(str(v["explanation"]))'''
new4 = '''                        if not _expl_ok(emp, wstart, v, w):
                            v["explanation"] = _factual_expl(emp, w, wstart, v)
                        if v.get("explanation"):
                            _e2 = _lc2.strip_think(str(v["explanation"]))'''
assert s2.count(old4) == 1, "B2"
s2 = s2.replace(old4, new4)
io.open(p2, "w", encoding="utf-8", newline="\n").write(s2)
print("B 完整度自检 ✓")
