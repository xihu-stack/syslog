"""检测器：按员工攒时间窗口 → 便宜触发门 → 本地 LLM 意图分析 → verdict。

覆盖三类日志信号：
- DOC：写类动作 / 敏感文件 / 非本地通道（U盘/网盘/移动存储）
- WEB：访问 网盘 / 个人邮箱 / 招聘网站
- SEARCH：搜索 求职词 / 高危词
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

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

# 遥测/自动更新类子域——LLM 判低分的例外,锚点不接管(拉到75会放大误判)
_TELEMETRY_PREFIX = ("st.", "abtest.", "ab.", "telemetry.", "tm.", "log.", "stat.",
                     "update.", "update-", "auto.", "dl.", "ws.", "wss.")


def anchor_score(intent, window, day_total=None) -> int | None:
    """确定性锚点分: 访问即违规类(policy_violation/data_exfiltration)按窗口客观
    特征统一定分,消除LLM打分抖动(2026-08-19用户要求: 同样的问题分数必须一致,
    基线/频次/时段等客观差异允许分层)。
    policy_violation(个人邮箱/网盘等禁止类): 访问即 75
    data_exfiltration(文件助手/外发通道): 基础 70
    修正: 高频(≥10次)+10 / 中频(≥4次)+5(频次用当日累计day_total——窗口只是
    60分钟切片,单窗口3次但全天10次的情况按10次分层,2026-08-19);DOC写/外发
    动作+10;深夜(22-7点)+5;封顶90
    频次与偏离驱动的场景(job_seeking/baseline_deviation)不接管——输入不同分不同,
    属可理解的客观差异。窗口全是遥测子域时不接管(保留LLM低分例外)。"""
    if intent not in ("policy_violation", "data_exfiltration") or not window:
        return None
    doms = [((getattr(e, "raw", None) or {}).get("domain") or "").lower()
            for e in window if getattr(e, "category", "") == "WEB"]
    doms = [d for d in doms if d]
    if doms and all(d.startswith(_TELEMETRY_PREFIX) for d in doms):
        return None
    hours = [e.occurred_at.hour for e in window if e.occurred_at]
    night = any(h < 7 or h >= 22 for h in hours)
    cnt = day_total if day_total else sum(e.count or 1 for e in window)
    has_write = any(e.category == "DOC" and e.action in WRITE_ACTIONS for e in window)
    score = 75 if intent == "policy_violation" else 70
    if intent == "data_exfiltration":
        if cnt >= 10:
            score += 10
        elif cnt >= 4:
            score += 5
    if has_write:
        score += 10
    if night:
        score += 5
    return min(score, 90)

SYSTEM_PROMPT = (
    "你是企业员工终端行为分析助手，识别数据外发、离职求职、违规等内部风险。\n"
    "输入：某员工一段时间窗口内的行为序列（可能附历史基线摘要、偏离信号、已知豁免）。\n"
    "输出 JSON：intent / deviation / risk_score(0-100整数) / explanation(一句中文) / channels。\n\n"
    "【公司策略——重要前提】\n"
    "个人邮箱、网盘/云盘 在公司【禁止使用】→ 任何访问即违规(policy_violation),不管时段。\n"
    "例外: OneDrive(storage.live.com/onedrive.live.com等)是公司采购的M365组件,不算网盘违规 → normal_work。\n"
    "微信文件助手(filehelper/文件传输助手)=传文件外发通道 → 访问即外发嫌疑(data_exfiltration)。\n"
    "【数据外发判定】data_exfiltration 须有真实外发动作/通道(网盘上传/邮箱发送/文件助手传文件/上传文件到AI)；仅浏览或反复用AI对话不算外发→归 baseline_deviation。\n"
    "普通微信访问(weixin.qq.com等)=正常办公,不算风险。\n"
    "远程控制(todesk等)=工具使用,降权(凌晨/密集才告警)。\n\n"
    "【评分锚点——严格按此打分】\n"
    "⚠ policy_violation 与 data_exfiltration 两类的 risk_score 由系统按统一规则计算(访问即违规=75/70+频次/时段/写动作修正),你的 risk_score 仅作参考——请把精力放在 explanation 的具体性上。\n"
    "• 个人邮箱/网盘(公司禁止) → 主动访问 65-75（访问即违规,不管时段）；但 update./自动更新/-debug/遥测等子域是软件后台联网、非员工主动操作 → 10-20\n"
    "• VPN/翻墙工具(privado/clash等) → 不算风险(业务规则:翻墙非违规),按常规浏览 5-15\n"
    "• 代码仓库(github/gitlab) → 40-55（代码外发嫌疑,看频次/时段）\n"
    "• 微信文件助手(传文件) → 70-80（外发嫌疑）。但【访问文件助手页面≠已传输文件】:窗口若只标注了页面/轮询访问(URL路径为静态资源/poll/get类),未见上传特征 → 30-45;URL含发送/上传特征(send/upload/file API)或伴大流量 → 70-80\n"
    "• 招聘网站分两档(2026-08-19用户口径):\n"
    "  【重点站: BOSS直聘(zhipin)/猎聘(liepin)/前程无忧(51job)/智联招聘(zhaopin)】访问即关注(公司口径:重点站任何访问必须立马关注):分数由系统锚点统一定(单次55/反复3-9次70/高频≥10次80,凌晨+5/跨天+10,封顶90),你的risk_score仅作参考;窗口含重点站访问→intent判job_seeking,explanation如实写域名+次数+时段+是否跨天。\n"
    "  【一般站: 领英linkedin及其他招聘平台】双用途(HR招聘/商务社交),工作时段低频→normal_work；反复高频或凌晨 → 系统按锚点定分(基础50+修正,封顶65),关注即可,分数明显低于重点站。严格按窗口标注的访问次数判断,不得脑补频次。\n"
    "• 远程控制 + 凌晨 → 55-65；工作时段 → 30-40（降权）\n"
    "• AI助手(chatgpt/deepseek/豆包/kimi/copilot等) → 工作时段低频(1-3次) 5-15(正常使用)；反复高频(≥10次)或凌晨 → 35-48, baseline_deviation(重度依赖AI、异常,但纯对话无外发动作≠数据外发)；仅当窗口同时含真实外发(上传文件到AI/网盘/邮箱/文件助手) → 才判 data_exfiltration 60-75\n"
    "• 凌晨 + 仅常规网站(无外发通道) → 25-35\n"
    "• 工作时段 + 常规网站/普通微信 → 5-15\n\n"
    "【跨天模式规则(结合近7天行为史判断)】①同类风险访问单日低频但累计≥4天(【每天仅1次也算】——累计天数是关键,不是单日频次) → 属进行中行为,招聘类【一律判 job_seeking 且分数≥50进告警】(重点站→60-70;一般站如领英→50-60,经常访问必须注意但分数不用太高;系统锚点已强制),explanation注明累计N天;②访问招聘网站+同期存在简历/离职类敏感文档操作 → job_seeking 65-80(强关联信号);③频率逐日爬坡 → 在①基础上再+5。孤立首次/单日低频不适用,严禁仅因行为史存在就无视当前窗口实际频次。\n"
    "【基线偏离的使用边界】'域名不在个人基线中'本身≠严重偏离——每人每天都会首次遇到大量新域名(见全局参照)。偏离档位必须综合:频次是否远超本人常态+时段(凌晨)+多外发通道叠加来判断;严禁仅以'首次出现/不在基线'把低频访问(≤5次)判为severe或抬进高危档。\n"
    "【intent 由窗口的主风险信号决定——勿被弱信号带偏】招聘网站【单次/低频夹杂在其他信号中≠job_seeking】:job_seeking 仅用于招聘网站反复高频(≥3次)/凌晨为主信号的窗口；若窗口主风险是邮箱/网盘/外发,按主风险定intent,不要因含1次领英/招聘就判求职。\n"
    "【intent 判定】个人邮箱/网盘(禁止) → policy_violation；VPN/翻墙 → normal_work(业务规则:翻墙非违规)；"
    "微信文件助手 → data_exfiltration；代码仓库 → baseline_deviation；"
    "招聘网站仅反复高频(≥3)/凌晨 → job_seeking（单次/低频 → normal_work）；远程控制 → baseline_deviation；"
    "AI助手反复高频访问(纯对话无外发) → baseline_deviation（低频 → normal_work；伴上传文件/真实外发通道 → data_exfiltration）；普通微信/正常办公 → normal_work。\n"
    "若基线摘要含'已知正常行为(豁免)'，同类行为判 normal_work。\n\n"
    "只输出 JSON：intent(data_exfiltration|job_seeking|baseline_deviation|policy_violation|normal_work), "
    "deviation(none|minor|major|severe), risk_score(0-100整数), "
    "explanation(一句中文,必须具体:含【域名+次数/频次+时段(凌晨/工作)+是否偏离个人基线】,禁止泛泛套话), "
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
    # 按信号强度分三档（让 AI 看清：强信号置顶 / 邮箱微信标低信号 / 常规弱化）
    high_sig, low_sig, normal = [], [], []
    for d, info in sorted(web.items(), key=lambda x: -x[1]["count"]):
        tier = dicts.risk_tier(d)
        if tier in ("high", "mid", "job"):
            high_sig.append((d, info))
        elif tier == "low":
            low_sig.append((d, info))
        else:
            normal.append((d, info))

    lines = []
    # 时段提示
    hours = [e.occurred_at.hour for e in window if e.category == "WEB" and e.occurred_at]
    if hours and (min(hours) < 7 or max(hours) >= 22):
        lines.append(f"[时段] 含非工作时段访问（{min(hours)}-{max(hours)}时），公司夜间无人需关注")

    # 强信号置顶 + 标注类别（远程控制/网盘/招聘）
    # ws./wss. 前缀是 WebSocket 长连接心跳计数(页面挂着就会持续+1),不代表主动操作次数——
    # 必须标注,防止 AI 被"×938"这类数字带偏而虚高打分(2026-08-18 gaoguanfei 案例)
    def _cnt_tag(d, n):
        if d.startswith("ws.") or d.startswith("wss."):
            return f"×{n}(连接心跳,非主动操作次数)"
        if d.startswith(("update.", "update-", "auto.")) or ".update." in d or d.startswith("dl."):
            return f"×{n}(软件自动更新/后台子域,非员工主动操作→按锚点应10-20分)"
        # st./abtest./telemetry./log. 遥测子域:客户端后台定时上报(每小时1条整点形态),
        # 凌晨出现不代表人在用(2026-08-19 胡曦todesk凌晨心跳误读案例)
        if d.startswith(("st.", "abtest.", "ab.", "telemetry.", "tm.", "log.", "stat.")):
            return f"×{n}(遥测心跳,客户端后台定时上报,非主动访问)"
        return f"×{n}"
    for d, info in high_sig[:10]:
        rc = dicts.risk_class(d)
        cat_tag = f"[{info['cat']}]" if info["cat"] else ""
        # 外发通道类域名附带URL路径样本(3个):让AI区分"打开页面/轮询"vs"真实上传/发送"
        path_hint = ""
        if rc and ("文件" in rc or "微信" in rc or "网盘" in rc or "邮箱" in rc):
            paths = list({(e.target_value or "").split("?")[0][-60:] for e in window
                          if e.category == "WEB" and d in ((e.raw or {}).get("domain") or "") and (e.target_value or "").count("/") >= 2})[:3]
            if paths:
                path_hint = " 路径样本:" + " | ".join(paths)
        lines.append(f"[⚠{rc}] {d} {_cnt_tag(d, info['count'])} {cat_tag}{path_hint}")
    # 低信号(个人邮箱/微信)：标注但明确"访问≠外发"，避免被当高危
    for d, info in low_sig[:8]:
        rc = dicts.risk_class(d)
        cat_tag = f"[{info['cat']}]" if info["cat"] else ""
        lines.append(f"[{rc}-低信号·访问非外发] {d} {_cnt_tag(d, info['count'])} {cat_tag}")
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
    # 外发通道工作时段密集访问(频次异常,不依赖基线,冷启动也算)
    _chan = Counter()
    for e in window:
        if e.category == "WEB":
            t = dicts.risk_tier((e.raw or {}).get("domain") or e.target_value)
            if t == "mid" and not _is_off_hours(e.occurred_at):  # 远程控制工作时段密集(频次异常)
                _chan[t] += 1
    if _chan and max(_chan.values()) >= 15:
        flags.append("channel_burst")
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
    # 只标注【新出现的 high/mid/job 级域名】——普通新域名数量是纯浏览噪音主因
    # （几乎每人每天上百个新域名）；个人邮箱/微信(low)新域名也不算偏离（全民日常）。
    risky_new = sorted({d for d in newdom if dicts.risk_tier(d) in ("high", "mid", "job")})
    if risky_new:
        flags.append("new_risky_domain:" + ",".join(risky_new[:5]))
    return flags


def should_trigger(window, dev, baseline) -> bool:
    """调用 AI 的时机：只在命中【真实风险信号】时才研判，避免对常规浏览浪费 AI 并产生噪音告警。

    信号（任一即触发）：
      - WEB 命中 high/mid/job 级域名（远程控制=high / 网盘=mid / 招聘=job）
      - WEB/DOC 非工作时段(凌晨0-6/深夜22+)活动（公司夜间无人，时段本身可疑）
      - DOC 写操作 / 非本地通道(USB/外发)
      - SEARCH 含求职/高危关键词
      - 冷启动用户 + 量激增
    注意：个人邮箱/微信(risk_tier=low)是全民日常行为，访问≠上传，【单独不触发】——
    这是上一版 203 条"个人邮箱"data_exfiltration 噪音告警(命中84/108用户)的根源。
    """
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
            dom = (e.raw or {}).get("domain") or e.target_value
            if dicts.is_heartbeat(dom):  # 客户端认证心跳——忽略
                continue
            tier = dicts.risk_tier(dom)
            if tier in ("high", "job"):  # 禁止类(邮箱/网盘/文件助手)+招聘→访问即触发
                return True
            if tier == "mid" and _is_off_hours(e.occurred_at):  # 远程控制+凌晨/深夜→触发
                return True
            # 搜索关键词(深信服keyword_original)匹配求职/高危→触发研判
            _kw = ((e.raw or {}).get("keyword_original") or "").strip()
            if _kw and (_search_risky(_kw) or any(t in _kw for t in dicts.get("job_search_terms"))):
                return True
    # 频次异常:外发通道工作时段密集访问(deviation算的channel_burst)
    if dev and "channel_burst" in dev:
        return True
    # 深夜(22-7)WEB活动: 非心跳/非遥测域名累计≥3条→触发(公司夜间无人需关注)。
    # 2026-08-19全员审计发现: 注释一直宣称有此触发但代码没实现——徐浩深夜
    # ftp.hp.com×155/outlook×130 完全零研判。遥测(wns./update.等)排除防噪音。
    _night_real = 0
    _mid_real = 0
    for e in window:
        if e.category != "WEB":
            continue
        dom = ((e.raw or {}).get("domain") or e.target_value or "").lower()
        if not dom or dicts.is_heartbeat(dom) or dom.startswith(_TELEMETRY_PREFIX):
            continue
        if _is_off_hours(e.occurred_at):
            _night_real += (e.count or 1)
        if dicts.risk_tier(dom) == "mid":
            _mid_real += (e.count or 1)
    if _night_real >= 3:
        return True
    # mid类(AI助手/远程控制/代码仓库)工作时段高频: ≥30次→触发研判。
    # 判出来通常35-48分不告警,但"重度依赖AI/常驻远控"在研判历史可见
    # (2026-08-19审计: 胥鑫容deepseek×137/万亮github×169系统里完全无痕)。
    # ws./wss.心跳计数已排除,30次门槛防日常使用误触。
    if _mid_real >= 30:
        return True
    # 冷启动用户 + 整体量激增
    if (not baseline or baseline.get("sample_count", 0) < 3) and dev and "volume_spike" in dev:
        return True
    return False


def _work_hours_cap(window, dev=None) -> int | None:
    """工作时段(不含凌晨/深夜)各类域名风险分上限。
    AI 不遵守锚点时硬兜底;外发通道频次异常(channel_burst)时信任AI高分不夹。"""
    if any(_is_off_hours(e.occurred_at) for e in window):
        return None  # 含非工作时段→凌晨高分保留
    if dev and "channel_burst" in dev:
        return None  # 外发通道密集(频次异常)→信任AI打分
    cap = 0
    for e in window:
        if e.category == "WEB":
            t = dicts.risk_tier((e.raw or {}).get("domain") or e.target_value)
            if t == "high":
                return None  # 窗口含禁止类(邮箱/网盘/文件助手)→不夹(旧版取max会把high夹到mid的40,外发被低估)
            cap = max(cap, {"mid": 40, "job": 85}.get(t, 0))  # 仅纯 mid/job 窗口才夹:远程控制40/招聘85
    return cap or None


def analyze_window(window: list[CanonicalEvent], profile=None, dev=None, exemptions=None, global_ctx=None,
                   model=None, history=None, day_ctx=None) -> dict:
    if profile:
        profile_txt = f"\n{profile}"
    else:
        # 冷启动：无个人基线——明确告诉 AI 不要因"个人偏离/陌生"加分，按全局参照+高危信号判断
        profile_txt = ("\n【个人基线】新用户/冷启动，无个人基线。"
                       "不要因'陌生/偏离基线'加分；仅凭【全局参照】+高危域名+凌晨时段判分。")
    dev_txt = f"\n偏离信号：{', '.join(dev)}" if dev else ""
    exempt_txt = f"\n已知正常行为（豁免）：{exemptions}" if exemptions else ""
    g_txt = f"\n{global_ctx}" if global_ctx else ""
    hist_txt = f"\n{history}" if history else ""
    day_txt = f"\n{day_ctx}" if day_ctx else ""
    user = (f"员工：{window[0].employee_id}（设备：{window[0].device_id}）\n"
            f"行为序列：\n{_fmt_window(window)}{g_txt}{profile_txt}{dev_txt}{exempt_txt}{hist_txt}{day_txt}\n\n"
            f"写explanation时:域名次数用『本窗口N次,今日累计M次』双口径(累计来自[当日累计]行),不要只写窗口次数让人误读为全天。请输出 JSON。")
    try:
        raw = llm_client.chat(
            [{"role": "system", "content": SYSTEM_PROMPT},
             {"role": "user", "content": user}],
            max_tokens=800, timeout=120, model=model,
        )
        v = llm_client.extract_json(raw)
        v.setdefault("explanation", raw[:120])
        v.setdefault("risk_score", 0)
        v.setdefault("intent", "unknown")
        v.setdefault("deviation", "none")
        v.setdefault("channels", [])
        v["ai_participated"] = True
        cap = _work_hours_cap(window, dev)
        if cap is not None and int(v.get("risk_score") or 0) > cap:
            v["risk_score"] = cap
            v["explanation"] = (v.get("explanation") or "").rstrip("。") + "（工作时段·已校准）"
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
            tier = dicts.risk_tier((e.raw or {}).get("domain") or e.target_value)
            off = _is_off_hours(e.occurred_at)
            if tier == "high":                      # 邮箱/网盘(禁止)/微信文件助手(外发)
                score = max(score, 75 if off else 65)
                rc = dicts.risk_class((e.raw or {}).get("domain") or e.target_value)
                channels.add({"个人邮箱": "personal_email", "网盘/云盘": "netdisk", "微信文件助手": "wechat_file"}.get(rc, "other"))
            elif tier == "job":                     # 招聘求职
                score = max(score, 75 if off else 55)
            elif tier == "mid":                     # 远程控制(降权)
                score = max(score, 55 if off else 35)
                channels.add("remote_control")
        if e.category == "SEARCH" and _search_risky(e.target_value):
            score = max(score, 50)
    return {
        "intent": "data_exfiltration" if score >= 60 else ("job_seeking" if score >= 50 else ("baseline_deviation" if score >= 30 else "normal_work")),
        "deviation": "major" if score >= 60 else ("minor" if score >= 30 else "none"),
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
