"""检测器：按员工攒时间窗口 → 便宜触发门 → 本地 LLM 意图分析 → verdict。

覆盖三类日志信号：
- DOC：写类动作 / 敏感文件 / 非本地通道（U盘/网盘/移动存储）
- WEB：访问 网盘 / 个人邮箱 / 招聘网站
- SEARCH：搜索 求职词 / 高危词
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Optional

import llm_client
import dicts
from models import CanonicalEvent

# 绝对风险模式：永远触发（不被基线"正常化"）
ABSOLUTE_RISK = ["招聘", "求职", "网盘", "远程控制", "个人邮箱", "todesk", "teamviewer",
                 "向日葵", "anydesk", "pan.baidu", "aliyundrive", "dropbox", "115.com"]

# 写类 / 外发类动作（文档侧）
WRITE_ACTIONS = {
    "COPY", "MOVE", "DELETE", "UPLOAD", "DOWNLOAD", "SEND", "PRINT",
    "RENAME", "CREATE", "MODIFY", "SAVE", "SAVE_AS", "CUT", "BURN",
}

WINDOW_GAP = timedelta(minutes=60)

SYSTEM_PROMPT = (
    "你是企业员工终端行为分析助手，识别数据泄露、离职等风险。\n"
    "输入：某员工一段时间窗口内的行为序列（可能附历史基线摘要和已知正常行为）。\n"
    "判断：意图、对【该员工个人基线】的偏离程度、风险分(0-100)、一句中文解释。\n\n"
    "【风险分层标准——必须严格遵守】\n"
    "90-100 严重(CRITICAL)：文档外发到U盘/网盘/个人邮箱 + 敏感文件 + 凌晨/规避\n"
    "75-89  高危(HIGH)：todesk等远程控制 + 凌晨(0-6点) + 招聘网站 + 拷敏感文档\n"
    "50-74  关注(MEDIUM)：工作时间访问招聘网站(非HR)、个人邮箱、大量新域名\n"
    "30-49  低风险(LOW)：冷启动偏离、非工作时段但无具体风险信号\n"
    "0-29   正常：上班时间正常办公\n\n"
    "【关键判分规则】\n"
    "1. 远程控制(todesk/teamviewer)：仅访问认证页面/后台连接=可能是软件自启动(开机挂着)，"
    "工作时间=50分；凌晨+大量其他异常=75+分；凌晨但只有todesk=60分(可能是自启动)\n"
    "2. 招聘网站：HR岗位(已知正常)=20分normal_work；非HR工作时间=60分；非HR凌晨=75分\n"
    "3. 文档操作(U盘/打印/外发)：敏感文件+外发通道=85+；常规文件+外发=60；本地读写=20\n"
    "4. 冷启动(无基线)：纯新域名浏览无具体信号=最多30分；不要因陌生就打高分\n"
    "5. 凌晨(0-6点)：仅时间异常无其他信号=40分；叠加招聘/远程/外发=75+分\n\n"
    "如果基线摘要中有'已知正常行为(豁免)'，同类行为判normal_work(0-20分)。\n"
    "只输出 JSON：intent(data_exfiltration|job_seeking|baseline_deviation|policy_violation|normal_work), "
    "deviation(none|minor|major|severe), risk_score(0-100整数), explanation(一句中文), "
    "channels(数组,取自 usb|netdisk|personal_email|upload|local)。"
)


def build_windows(events: list[CanonicalEvent]) -> dict[str, list[list[CanonicalEvent]]]:
    by_emp: dict[str, list[CanonicalEvent]] = defaultdict(list)
    for e in events:
        by_emp[e.employee_id].append(e)
    result: dict[str, list[list[CanonicalEvent]]] = {}
    for emp, evs in by_emp.items():
        evs = sorted(evs, key=lambda x: x.occurred_at)
        win, windows = [evs[0]], []
        for e in evs[1:]:
            if e.occurred_at - win[-1].occurred_at <= WINDOW_GAP:
                win.append(e)
            else:
                windows.append(win)
                win = [e]
        windows.append(win)
        result[emp] = windows
    return result


def is_sensitive(text: str) -> bool:
    t = text or ""
    return any(k in t for k in dicts.get("sensitive_keywords"))


def _search_risky(kw: str) -> bool:
    terms = dicts.get("job_search_terms") + dicts.get("risk_search_terms")
    return any(t in (kw or "") for t in terms) or is_sensitive(kw)


def trigger(window: list[CanonicalEvent]) -> bool:
    """全自动触发门：不依赖用户关键词。
    文档写类动作 / 非本地通道 / 任何网页访问 / 任何搜索 → 都送 AI 判断；
    仅"纯本地只读(ACCESS/READ)"跳过（太常规）。风险识别全部交给 AI 语义判断。"""
    for e in window:
        if e.category == "DOC":
            if e.action in WRITE_ACTIONS:
                return True
            ch = e.raw.get("channel")
            if ch and ch != "LOCAL":
                return True
        elif e.category in ("WEB", "SEARCH"):
            return True
    return False


def _fmt_window(window: list[CanonicalEvent]) -> str:
    """格式化窗口给 LLM：网页按域名聚合计数(取Top15)、文档/搜索按时间(最多12条)，整体限长避免超上下文。"""
    SRC = {"ipguard":"IP-Guard","sangfor":"深信服","":"未知"}
    web = defaultdict(int)
    others = []
    for e in window:
        if e.category == "WEB":
            web[(e.raw or {}).get("domain") or e.target_value] += (e.count or 1)
        else:
            others.append(e)
    lines = []
    for d, c in sorted(web.items(), key=lambda x: -x[1])[:15]:
        lines.append(f"[访问网页] {d} ×{c}")
    if len(web) > 15:
        lines.append(f"…及另外 {len(web) - 15} 个域名")
    n_other = len(others)
    for e in others[:12]:
        t = e.occurred_at.strftime("%m-%d %H:%M")
        src = SRC.get(getattr(e,'source',''),'')
        if e.category == "SEARCH":
            lines.append(f"{t} [{src}] [搜索] \"{e.target_value}\"")
        else:
            lines.append(f"{t} [{src}] [{e.action}] {e.target_value}（通道={(e.raw or {}).get('channel')}, 应用={(e.raw or {}).get('application')}）")
    if n_other > 12:
        lines.append(f"…及另外 {n_other - 12} 条文档/搜索")
    return "\n".join(lines) if lines else "(无行为)"


def deviation(window, baseline, global_domains=None) -> list:
    """数值化偏离信号（vs 该员工历史基线 + 全局通用域名）。"""
    flags = []
    if not baseline or baseline.get("sample_count", 0) < 3:
        return flags
    gdom = global_domains or set()
    hrs = set(baseline.get("active_hours_top", []))
    wh = {e.occurred_at.hour for e in window}
    if wh and (min(wh) < 8 or max(wh) > 20) and not wh.issubset(hrs):
        flags.append("off_hours")
    med = baseline.get("daily_doc_op_median", 0)
    if med and len(window) > max(5, med * 3):
        flags.append("volume_spike")
    bch = set(baseline.get("channels_used", []))
    new_ch = sorted({(e.raw or {}).get("channel") for e in window} - bch - {None, ""})
    if new_ch:
        flags.append("new_channel:" + ",".join(new_ch))
    bdom = set(baseline.get("common_domains", [])) | gdom
    newdom = sorted({(e.raw or {}).get("domain") for e in window if e.category == "WEB"
                     and (e.raw or {}).get("domain") and (e.raw or {}).get("domain") not in bdom})
    if newdom:
        flags.append("new_domain:" + ",".join(newdom[:5]))
    return flags


def should_trigger(window, dev, baseline) -> bool:
    """基线感知触发：无基线 / 有偏离 / 写操作 / 外发通道 / 绝对风险 → 调 AI；常规行为 → 跳过。"""
    if not baseline or baseline.get("sample_count", 0) < 3:
        return True
    if dev:
        return True
    for e in window:
        if e.category == "DOC" and e.action in WRITE_ACTIONS:
            return True
        ch = (e.raw or {}).get("channel")
        if ch and ch != "LOCAL":
            return True
        # 绝对风险：招聘/网盘/远程控制/个人邮箱 → 永远触发（不被基线正常化）
        cat = ((e.raw or {}).get("category") or "") + " " + ((e.raw or {}).get("domain") or "")
        if any(p in cat.lower() for p in ABSOLUTE_RISK):
            return True
    return False


def analyze_window(window: list[CanonicalEvent], profile=None, dev=None, exemptions=None) -> dict:
    profile_txt = f"\n历史基线摘要：{profile}" if profile else "\n历史基线摘要：（暂无，按通用可疑度判断）"
    dev_txt = f"\n偏离信号：{', '.join(dev)}" if dev else ""
    exempt_txt = f"\n已知正常行为（豁免）：{exemptions}" if exemptions else ""
    user = (f"员工：{window[0].employee_id}（设备：{window[0].device_id}）\n"
            f"行为序列：\n{_fmt_window(window)}{profile_txt}{dev_txt}{exempt_txt}\n\n请输出 JSON。")
    try:
        raw = llm_client.chat(
            [{"role": "system", "content": SYSTEM_PROMPT},
             {"role": "user", "content": user}],
            max_tokens=500, timeout=120,
        )
        v = llm_client.extract_json(raw)
        v.setdefault("explanation", raw[:120])
        v.setdefault("risk_score", 0)
        v.setdefault("intent", "unknown")
        v.setdefault("deviation", "none")
        v.setdefault("channels", [])
        v["ai_participated"] = True
        return v
    except Exception as ex:
        return _fallback_verdict(window, str(ex))


def _fallback_verdict(window: list[CanonicalEvent], err: str) -> dict:
    score = 0
    channels = set()
    for e in window:
        ch = e.raw.get("channel")
        if e.category == "DOC" and e.action in ("UPLOAD", "SEND", "COPY") and ch and ch != "LOCAL":
            score = max(score, 70); channels.add(ch)
        if e.category == "DOC" and is_sensitive(e.target_value) and e.action in WRITE_ACTIONS:
            score = max(score, 60)
        if e.category == "WEB" and e.raw.get("domain_class") in ("netdisk", "personal_email"):
            score = max(score, 55); channels.add(e.raw.get("domain_class"))
        if e.category == "SEARCH" and _search_risky(e.target_value):
            score = max(score, 50)
    return {
        "intent": "data_exfiltration" if score >= 60 else ("job_seeking" if score >= 50 else "normal_work"),
        "deviation": "major" if score >= 60 else "none",
        "risk_score": score,
        "explanation": f"[规则兜底-LLM不可用] {err[:40]}",
        "channels": list(channels),
        "ai_participated": False,
    }


def detect(events, risk_threshold: int = 50):
    """简易研判（演示/CLI 用，无 DB 基线）：所有窗口都研判。"""
    windows_by_emp = build_windows(events)
    verdicts, alerts = [], []
    for emp, wins in windows_by_emp.items():
        for w in wins:
            dev = deviation(w, {})
            if not should_trigger(w, dev, {}):
                continue
            v = analyze_window(w, None, dev)
            item = {"employee": emp, "device": w[0].device_id,
                    "window_start": w[0].occurred_at, "window_end": w[-1].occurred_at,
                    "events": w, "verdict": v}
            verdicts.append(item)
            if v.get("risk_score", 0) >= risk_threshold:
                alerts.append(item)
    return verdicts, alerts
