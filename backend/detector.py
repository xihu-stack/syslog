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

# 高危域名识别统一走 dicts.risk_class（可经后台字典面板增删，见 dicts.risk_patterns）

# 写类 / 外发类动作（文档侧）
WRITE_ACTIONS = {
    "COPY", "MOVE", "DELETE", "UPLOAD", "DOWNLOAD", "SEND", "PRINT",
    "RENAME", "CREATE", "MODIFY", "SAVE", "SAVE_AS", "CUT", "BURN",
}

WINDOW_GAP = timedelta(minutes=60)

SYSTEM_PROMPT = (
    "你是企业员工终端行为分析助手，识别数据外发、离职求职、违规等内部风险。\n"
    "输入：某员工一段时间窗口内的行为序列（可能附历史基线摘要、偏离信号、已知豁免）。\n"
    "输出 JSON：intent / deviation / risk_score(0-100整数) / explanation(一句中文) / channels。\n\n"
    "【评分锚点——严格按此打分，保证跨样本一致】\n"
    "• 凌晨(0-6点) + 高危域名(远程控制/网盘/个人邮箱/微信传输) → 75-85\n"
    "• 工作时段 + 高危域名(远程控制/网盘/个人邮箱/微信传输) → 50-65\n"
    "• 非HR岗位访问招聘网站：工作时段 55-65；凌晨 70-80\n"
    "• 文档外发(U盘/网盘/邮件发送)+敏感文件 → 85+；常规文件外发 → 60\n"
    "• 凌晨(0-6点) + 仅常规网站(无高危域名) → 35-45\n"
    "• 工作时段 + 常规网站(无高危域名) → 10-25\n\n"
    "【关键——主动抑制噪音】\n"
    "• '访问大量陌生域名 / 新域名多' 单独【不构成风险】，最高 25 分。"
    "陌生域名数量在纯网页浏览场景下没有意义，几乎所有人每天都会访问上百个不同域名。\n"
    "• 只有当陌生域名中【含高危类别】(网盘/求职/远程控制/个人邮箱/微信传输)，"
    "或【叠加凌晨时段】，才允许上 50 分。\n"
    "• 银行/IT/新闻/搜索引擎/政府/教育/医疗 等正常行业网站 = 正常办公，不计风险。\n\n"
    "【intent 判定】\n"
    "远程控制/网盘/个人邮箱/微信传输 → data_exfiltration；招聘网站 → job_seeking；\n"
    "凌晨+高危域名 → data_exfiltration；仅凌晨+常规网站 → baseline_deviation；正常办公 → normal_work。\n"
    "若基线摘要含'已知正常行为(豁免)'，同类行为判 normal_work。\n\n"
    "只输出 JSON：intent(data_exfiltration|job_seeking|baseline_deviation|policy_violation|normal_work), "
    "deviation(none|minor|major|severe), risk_score(0-100整数), explanation(一句中文), "
    "channels(数组,取自 usb|netdisk|personal_email|upload|local|remote_control)。"
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
            ch = (e.raw or {}).get("channel")
            if ch and ch != "LOCAL":
                return True
        elif e.category in ("WEB", "SEARCH"):
            return True
    return False


def _is_off_hours(dt) -> bool:
    """非工作时段：0-6 点（凌晨）或 22-23 点（深夜）。"""
    h = dt.hour if dt else None
    return h is not None and (h < 7 or h >= 22)


def _fmt_window(window: list[CanonicalEvent]) -> str:
    """格式化窗口给 LLM。

    关键：高危域名访问单独高亮置顶、与常规浏览分开，避免被大量正常域名稀释；
    标注非工作时段。常规域名只取 Top15 + 计数，文档/搜索按时间最多12条。整体限长。"""
    SRC = {"ipguard": "IP-Guard", "sangfor": "深信服", "": "未知"}
    web = defaultdict(lambda: {"count": 0, "cat": ""})
    others = []
    for e in window:
        if e.category == "WEB":
            d = (e.raw or {}).get("domain") or e.target_value
            cat = (e.raw or {}).get("app") or (e.raw or {}).get("category") or ""
            web[d]["count"] += (e.count or 1)
            if cat and not web[d]["cat"]:
                web[d]["cat"] = cat
        else:
            others.append(e)
    # 高危域名 vs 常规域名 分开（核心降噪：不让 todesk 被淹没在 baidu 里）
    risky, normal = [], []
    for d, info in sorted(web.items(), key=lambda x: -x[1]["count"]):
        (risky if dicts.risk_class(d) else normal).append((d, info))

    lines = []
    # 时段提示
    hours = [e.occurred_at.hour for e in window if e.category == "WEB" and e.occurred_at]
    if hours and (min(hours) < 7 or max(hours) >= 22):
        lines.append(f"[时段] 含非工作时段访问（{min(hours)}-{max(hours)}时），需重点关注")

    # 高危访问置顶 + 标注类别
    for d, info in risky[:10]:
        rc = dicts.risk_class(d)
        cat_tag = f"[{info['cat']}]" if info["cat"] else ""
        lines.append(f"[⚠高危-{rc}] {d} ×{info['count']} {cat_tag}")
    # 常规访问（仅 Top15，弱化"数量"）
    for d, info in normal[:15]:
        cat_tag = f"[{info['cat']}]" if info["cat"] else ""
        lines.append(f"[访问网页] {d} ×{info['count']} {cat_tag}")
    if len(normal) > 15:
        lines.append(f"…及另外 {len(normal) - 15} 个常规域名（均非高风险）")

    n_other = len(others)
    for e in others[:12]:
        t = e.occurred_at.strftime("%m-%d %H:%M")
        src = SRC.get(getattr(e, 'source', ''), '')
        if e.category == "SEARCH":
            lines.append(f"{t} [{src}] [搜索] \"{e.target_value}\"")
        else:
            lines.append(f"{t} [{src}] [{e.action}] {e.target_value}（通道={(e.raw or {}).get('channel')}, 应用={(e.raw or {}).get('application')}）")
    if n_other > 12:
        lines.append(f"…及另外 {n_other - 12} 条文档/搜索")
    raw = "\n".join(lines) if lines else "(无行为)"
    # 硬截断：超过 1500 字（约 2000 tokens）则截断（留空间给 system prompt + 输出）
    if len(raw) > 1500:
        raw = raw[:1500] + "\n…（行为过多已截断）"
    return raw


def deviation(window, baseline, global_domains=None) -> list:
    """数值化偏离信号（vs 该员工历史基线 + 全局通用域名）。"""
    flags = []
    if not baseline or baseline.get("sample_count", 0) < 3:
        return flags
    gdom = global_domains or set()
    hrs = set(baseline.get("active_hours_top", []))
    wh = {e.occurred_at.hour for e in window}
    # 与 should_trigger._is_off_hours 对齐：凌晨0-6 / 深夜22+；且不在该员工常规时段
    if wh and (min(wh) < 7 or max(wh) >= 22) and not wh.issubset(hrs):
        flags.append("off_hours")
    med = baseline.get("daily_doc_op_median", 0)
    if med and len(window) > max(5, med * 3):
        flags.append("volume_spike")
    bch = set(baseline.get("channels_used", []))
    new_ch = sorted({(e.raw or {}).get("channel") for e in window} - bch - {None, ""})
    if new_ch:
        flags.append("new_channel:" + ",".join(new_ch))
    bdom = set(baseline.get("common_domains", [])) | gdom
    newdom = {(e.raw or {}).get("domain") for e in window if e.category == "WEB"
              and (e.raw or {}).get("domain") and (e.raw or {}).get("domain") not in bdom}
    # 只标注【新高危域名】——普通新域名数量在纯浏览场景下是噪音主因
    # （几乎每人每天上百个新域名），不作为偏离信号；只提示新出现的高危类别。
    risky_new = sorted({d for d in newdom if dicts.risk_class(d)})
    if risky_new:
        flags.append("new_risky_domain:" + ",".join(risky_new[:5]))
    return flags


def should_trigger(window, dev, baseline) -> bool:
    """调用 AI 的时机：只在命中【真实风险信号】时才研判，避免对常规浏览浪费 AI 并产生噪音告警。

    信号（任一即触发）：
      - WEB 命中高危域名（远程控制/网盘/个人邮箱/招聘/微信传输）
      - WEB/DOC 非工作时段(凌晨0-6/深夜22+)活动
      - DOC 写操作 / 非本地通道(USB/外发)
      - SEARCH 含求职/高危关键词
      - 冷启动用户 + 量激增
    常规工作时段浏览正常网站 → 跳过（这是此前 126 条"陌生域名"噪音告警的根源）。
    """
    has_off_hours = False
    has_risk_domain = False
    for e in window:
        if e.category == "DOC":
            if e.action in WRITE_ACTIONS:
                return True
            ch = (e.raw or {}).get("channel")
            if ch and ch != "LOCAL":
                return True
        if e.category == "SEARCH" and _search_risky(e.target_value):
            return True
        if e.category == "WEB":
            if dicts.risk_class((e.raw or {}).get("domain") or e.target_value):
                has_risk_domain = True
            if _is_off_hours(e.occurred_at):
                has_off_hours = True
    if has_risk_domain:
        return True
    if has_off_hours:
        return True
    # 冷启动用户 + 明显量激增（非纯常规浏览）
    if (not baseline or baseline.get("sample_count", 0) < 3) and dev and "volume_spike" in dev:
        return True
    return False


def analyze_window(window: list[CanonicalEvent], profile=None, dev=None, exemptions=None, global_ctx=None) -> dict:
    if profile:
        profile_txt = f"\n{profile}"
    else:
        # 冷启动：无个人基线——明确告诉 AI 不要因"个人偏离/陌生"加分，按全局参照+高危信号判断
        profile_txt = ("\n【个人基线】新用户/冷启动，无个人基线。"
                       "不要因'陌生/偏离基线'加分；仅凭【全局参照】+高危域名+凌晨时段判分。")
    dev_txt = f"\n偏离信号：{', '.join(dev)}" if dev else ""
    exempt_txt = f"\n已知正常行为（豁免）：{exemptions}" if exemptions else ""
    g_txt = f"\n{global_ctx}" if global_ctx else ""
    user = (f"员工：{window[0].employee_id}（设备：{window[0].device_id}）\n"
            f"行为序列：\n{_fmt_window(window)}{g_txt}{profile_txt}{dev_txt}{exempt_txt}\n\n请输出 JSON。")
    try:
        raw = llm_client.chat(
            [{"role": "system", "content": SYSTEM_PROMPT},
             {"role": "user", "content": user}],
            max_tokens=800, timeout=120,
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
        ch = (e.raw or {}).get("channel")
        if e.category == "DOC" and e.action in ("UPLOAD", "SEND", "COPY") and ch and ch != "LOCAL":
            score = max(score, 70); channels.add(ch)
        if e.category == "DOC" and is_sensitive(e.target_value) and e.action in WRITE_ACTIONS:
            score = max(score, 60)
        if e.category == "WEB":
            rc = dicts.risk_class((e.raw or {}).get("domain") or e.target_value)
            if rc:
                # 网盘/个人邮箱/远程控制/微信传输 → 兜底中危（LLM 不可用时）
                score = max(score, 60 if rc in ("远程控制", "网盘/云盘") else 55)
                ch_map = {"远程控制": "remote_control", "网盘/云盘": "netdisk",
                          "个人邮箱": "personal_email", "微信传输": "upload"}
                if rc in ch_map:
                    channels.add(ch_map[rc])
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
