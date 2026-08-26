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

# 噪声文档路径(2026-08-20): 只保留"结构事实"——系统/程序目录是客观位置,
# 不是语义判断;文件名是否缓存/敏感一律由本地AI判断(用户口径: 不写死关键词)
_NOISE_PATH = ("appdata", "programdata", "program files", "windows", "/windows/",
               "\\temp\\", "/temp/", ".cache", "node_modules", ".git")


def is_noise_doc(e) -> bool:
    """系统/程序目录内的文档操作=程序自写,不触发研判(结构性排除);
    文件名层面的缓存/敏感语义由AI判断,不做关键词枚举。"""
    if getattr(e, "category", "") != "DOC":
        return False
    if e.action in ("SEND", "UPLOAD", "PRINT", "BURN"):
        return False  # 外发/打印类是真实动作,交给AI按文件名语义判断
    p = ((e.raw or {}).get("src_path") or "").lower() + (e.target_value or "").lower()
    return any(k in p for k in _NOISE_PATH)

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
    # 证据前置(2026-08-21): 窗口须含本场景真实证据(禁止类域名/文件助手/非本地
    # DOC通道),锚点才接管——否则AI把微软登录/未识别应用的夜间流量误标policy时,
    # 锚点会把错误意图锁进75+档(潘利锋凌晨案例,selfheal连续多轮对齐暴露)
    def _wl_dest(e):
        """DOC外发目的地在公司豁免白名单(OA/费控等内部业务平台)→不算外发风险。"""
        d = dicts.dest_host(e.raw or {})  # 统一共享工具(URL主机+剥端口): 私有副本曾漏剥端口
        if d:
            return any(d == w or d.endswith("." + w) for w in dicts.get("risk_whitelist_domains") or [])
        # 网页上传无目标域名(2026-08-24鄢荣梅案例): msedgewebview2.exe上传IPG不记
        # 目的地,只标NETWORK——按±3分钟内浏览的公司白名单域名推断(Teams/M365/
        # SharePoint传附件),同期只有公司平台流量则视为公司通道
        _wl = [w.lower() for w in dicts.get("risk_whitelist_domains") or []]
        ts = getattr(e, "occurred_at", None)
        if ts is None:
            return False
        from datetime import timedelta as _td
        for w in window:
            if w.category != "WEB" or w.occurred_at is None:
                continue
            if abs((w.occurred_at - ts).total_seconds()) <= 180:
                d2 = ((w.raw or {}).get("domain") or "").lower()
                if d2 and any(d2 == x or d2.endswith("." + x) for x in _wl):
                    return True
        return False
    _has_evidence = any(dicts.risk_class(d) in ("网盘/云盘", "个人邮箱", "微信文件助手")
                        for d in doms) or any(
        e.category == "DOC" and not _wl_dest(e)
        and ((e.raw or {}).get("channel") not in (None, "", "LOCAL")
             or e.action in ("SEND", "UPLOAD", "PRINT", "BURN"))
        for e in window)
    if not _has_evidence:
        return None
    hours = [e.occurred_at.hour for e in window if e.occurred_at]
    night = any(h < 7 or h >= 22 for h in hours)
    cnt = day_total if day_total else sum(e.count or 1 for e in window)
    # 本地写+10=预谋信号(编辑/生成文档后外发)。但图片类排除(2026-08-24):
    # 截图发送前必然先落盘保存,系统行为被误当预谋→所有截图外发机械顶到90,
    # 与敏感文档外发同级,稀释最高档区分度(田纪元1张SendPhotoes.png=90案例)
    _IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".heic")
    has_write = any(e.category == "DOC" and e.action in WRITE_ACTIONS
                    and not str(e.target_value or "").lower().endswith(_IMG_EXT)
                    for e in window)
    score = 75 if intent == "policy_violation" else 70
    if intent == "data_exfiltration":
        if cnt >= 10:
            score += 10
        elif cnt >= 4:
            score += 5
    if has_write:
        score += 10
    # IPG实锤外发分层(2026-08-20): 文件确实离开本机——
    # 目的地=网页上传工具/个人邮箱/网盘(稀有通道) 85;微信(日常高频) 80;
    # 目的地稀有度分层: 网盘/个人邮箱等稀有通道85,微信等日常通道80;
    # 文件名是否敏感不在此判断——AI在说明里定性,锚点只管动作+通道的客观强度
    _send_evs = [e for e in window if e.category == "DOC" and e.action in ("SEND", "UPLOAD")
                 and (e.raw or {}).get("channel") not in (None, "", "LOCAL")
                 and not _wl_dest(e)]
    _send_dests = [dicts.dest_host(e.raw or {}) for e in _send_evs]
    if _send_dests:
        _rare = any(dicts.risk_class(d) in ("网盘/云盘", "个人邮箱") for d in _send_dests)
        # 单次纯图片外发(2026-08-26用户拍板): 一张截图与一份试验方案不该同档——
        # 日常通道80→75;高频(当日≥4次+5)会把常发截图的人抬回80,只降偶发
        _IMG2 = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".heic")
        _single_img = (len(_send_evs) == 1
                       and str(_send_evs[0].target_value or "").lower().endswith(_IMG2))
        _floor = 85 if _rare else (75 if _single_img else 80)
        if _single_img and cnt >= 4:
            _floor = 80  # 高频(当日≥4次)吃回降分: 常发截图的人不降
        # 默认名截图族(2026-08-26审计,任莉/姜苏泽案例): 整窗外发全是SendPhotoes/
        # 微信图片/屏幕截图这类系统默认名(与file_sensitivity"无语义默认名"同口径)
        # 且目的地非稀有通道时,不吃微信日常通道80档——单张75(用户拍板),高频
        # 多张也只维持75,让频次/深夜修正自己说话;真落到网盘/邮箱(稀有通道)不降
        _AUTO_NAME = ("sendphotoes", "微信图片", "屏幕截图", "screenshot", "mmexport")
        _all_auto = all(any(k in str(e.target_value or "").lower() for k in _AUTO_NAME)
                        for e in _send_evs)
        if _all_auto and not _rare:
            _floor = min(_floor, 75)
        score = max(score, _floor)
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
    "公司OA/费控平台xft.cmbchina.com是内部业务系统: 向其发送发票/报销/订单文件属正常办公(推断为报销流程),不判外发。\n"
    "微软基础设施域(login.mso.msidentity.com/ak.privatelink.msidentity.com/windowsupdate*/cloud.microsoft/office.com的登录与更新流量)是公司M365与操作系统组件,不是个人邮箱,判normal_work;个人邮箱仅指消费者邮箱服务(outlook.live.com个人版/gmail/qq/163等)。Teams是公司办公通讯软件,使用/会议/文件共享一律正常;outlook.cloud.microsoft/outlook.office.com网页版等企业邮箱发送附件属公司邮件通道,不判外发。\n"
    "公司自有域名规则(2026-08-26): huashen.bio 与 helixon.com 是公司主域,其任何子域、任何端口都是公司内部系统(如eln.=ELN电子实验记录本、lab.=实验平台、sftp.=内网传输、huashen.certara.net=仿真平台租户、prod-bioengine.cluster.helixon.com=内部集群、helixoncn*.sharepoint.com=公司M365)——向这些系统上传实验数据/文档一律 normal_work,严禁判外发/网盘违规/'未经授权上传'。判断公司系统看主域后缀,不要枚举记忆。helixoncn-my.sharepoint.com/personal/用户名_helixon_com/ 路径=公司M365个人OneDrive(Teams聊天附件存此处),是公司系统;onedrive.live.com/storage.live.com=公司M365 OneDrive(2026-08-26管理员确认加白),向其同步/上传文件属正常办公。\n"
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
    "  【重点站: BOSS直聘(zhipin)/猎聘(liepin)/前程无忧(51job)/智联招聘(zhaopin)】访问即关注(公司口径:重点站任何访问必须立马关注):分数由系统锚点统一定(单次75/反复3-9次85/高频≥10次90,凌晨+5/跨天+5,封顶95——全系统最高档,均不低于邮箱/外发同档),你的risk_score仅作参考;窗口含重点站访问→intent判job_seeking,explanation如实写域名+次数+时段+是否跨天。\n"
    "  领英(linkedin)与苏州人才网(hrss.suzhou)经公司确认属正常业务行为,访问不算求职信号(normal_work),勿因它们判job_seeking。其他招聘平台(脉脉/看准/卓聘等):反复高频或凌晨才考虑求职(系统锚点定分,基础55)。严格按窗口标注的访问次数判断,不得脑补频次。\n"
    "• 远程控制 + 凌晨 → 55-65；工作时段 → 30-40（降权）\n"
    "• AI助手(chatgpt/deepseek/豆包/kimi/copilot等) → 工作时段低频(1-3次) 5-15(正常使用)；反复高频(≥10次)或凌晨 → 35-48, baseline_deviation(重度依赖AI、异常,但纯对话无外发动作≠数据外发)；仅当窗口同时含真实外发(上传文件到AI/网盘/邮箱/文件助手) → 才判 data_exfiltration 60-75\n"
    "• 凌晨 + 仅常规网站(无外发通道) → 25-35\n"
    "• 工作时段 + 常规网站/普通微信 → 5-15\n\n"
    "【跨天模式规则(结合近7天行为史判断)】①同类风险访问单日低频但累计≥4天(【每天仅1次也算】——累计天数是关键,不是单日频次) → 属进行中行为,招聘类【一律判 job_seeking 且分数≥50进告警】(重点站→60-70;一般站如领英→50-60,经常访问必须注意但分数不用太高;系统锚点已强制),explanation注明累计N天;②访问招聘网站+同期存在简历/离职类敏感文档操作 → job_seeking 65-80(强关联信号);③频率逐日爬坡 → 在①基础上再+5。孤立首次/单日低频不适用,严禁仅因行为史存在就无视当前窗口实际频次。\n"
    "【风险域名不属于基线】招聘/网盘/邮箱/文件助手等风险类域名【永不计入个人基线或全局常见】——即使该员工天天访问、即使在其常用域名中,也绝不构成正常理由;天天访问恰是进行中风险信号(跨天模式)。\n"
    "【基线偏离的使用边界】'域名不在个人基线中'本身≠严重偏离——每人每天都会首次遇到大量新域名(见全局参照)。偏离档位必须综合:频次是否远超本人常态+时段(凌晨)+多外发通道叠加来判断;严禁仅以'首次出现/不在基线'把低频访问(≤5次)判为severe或抬进高危档。\n"
    "【intent 由窗口的主风险信号决定——勿被弱信号带偏】招聘网站【单次/低频夹杂在其他信号中≠job_seeking】:job_seeking 仅用于招聘网站反复高频(≥3次)/凌晨为主信号的窗口；若窗口主风险是邮箱/网盘/外发,按主风险定intent,不要因含1次领英/招聘就判求职。\n"
    "【浏览器标签标题——语义自主判断】URL旁的《标题》是页面内容的直接证据,如何解读由你判断:同一个人访问同一类网站,标题揭示的真实意图可能完全不同(如招聘相关页面,到底是在做招聘工作还是自己在找工作;邮箱/网盘页面是登录页还是操作页)。禁止仅凭域名类别下结论,必须结合标题语义定意图与分档;explanation引用关键标题原文作为依据。\n"
    "【外发深度分析——三问(2026-08-21)】窗口含 SEND/UPLOAD 到网络目的地时,explanation 必须依次回答:①目的地是什么:按域名语义判断服务性质(厂商官网/云SaaS分析平台/个人网盘/邮箱/内部系统/未知),这是风险定性的关键;②文件是什么:按扩展名与命名推断内容类型和敏感性(实验原始数据/设计源文件/数据库/办公文档/日志缓存),未知格式结合业务语境;③外发之外还有什么风险:数据离开公司控制进入第三方处理、科研/业务数据资产流失、合规与数据出境、供应商安全不可评估等。范式: 『.fcs流式标本文件→云分析SaaS』不只是外发,而是实验数据进入第三方平台处理,涉及科研资产与合规。\n"
    "【语义判断总则——不依赖固定词表】文件名/搜索词/标题的敏感性、意图方向,全部由你按语义判断:文件名看内容性质(项目资料/试验记录/合同客户/财务/个人证件/纯缓存或临时文件),搜索词看意图(求职流程/数据带出/规避审计/正常工作疑问),同一文件名在不同路径语境下意义不同。判断依据写进explanation,不要引用任何『关键词表』。\n"
    "【intent 判定】个人邮箱/网盘(禁止) → policy_violation；VPN/翻墙 → normal_work(业务规则:翻墙非违规)；"
    "微信文件助手 → data_exfiltration；代码仓库 → baseline_deviation；"
    "招聘网站仅反复高频(≥3)/凌晨 → job_seeking（单次/低频 → normal_work）；远程控制 → baseline_deviation；"
    "AI助手反复高频访问(纯对话无外发) → baseline_deviation（低频 → normal_work；伴上传文件/真实外发通道 → data_exfiltration）；普通微信/正常办公 → normal_work。\n"
    "若基线摘要含'已知正常行为(豁免)'，同类行为判 normal_work。\n\n"
    "输出 JSON 字段：intent(data_exfiltration|job_seeking|baseline_deviation|policy_violation|normal_work), "
    "deviation(none|minor|major|severe), risk_score(0-100整数), "
    "file_sensitivity(仅外发类窗口必填: high|mid|none)——按文件名+扩展名+上下文推断内容敏感性,与次数大小无关:high=实验/临床/项目数据(试验报告/测序/序列/数据包/文库)、合同财务、数据库导出、设计源文件——【必须文件名本身含明确证据(项目编号/试验术语/合同财务词),无语义默认名(SendPhotoes/微信图片/截图/新建文件/乱码哈希)一律none,严禁『可能包含/推断可能』式抬高】;mid=办公文档但含项目编号或内部术语;none=临时缓存/系统文件/私人生活文件(个人照片/购物/家人), "
    "explanation格式(5W,严格执行):【谁】在【何时(日期+时段)】通过【通道(应用/域名/设备)】【干了什么(动作+对象:文件名或域名×次数+文件大小)】,属于【问题定性(场景+风险含义)】。例: 张三在08-20凌晨通过微信文件助手发送『HX15001试验手册.pdf』等3个文件(共2.1MB),属数据外发。"
    "【方向铁律】行为序列中标注[↓收]的动作(下载/接收)是数据**进入**本机——严禁在explanation里把下载/接收的文件定性为外发对象或外发内容;外发只能引用[↑发](SEND/UPLOAD/PRINT/BURN)动作的文件;下载仅可作为行为上下文提及。\n"
    "【通道具体性铁律】explanation的通道禁止写『网络/通过网络/网络通道』这类空泛词——必须用输入中给出的具体应用名(如msedgewebview2.exe/Weixin.exe/OUTLOOK.EXE)或域名;目的地未记录时如实写『目的地未记录(网页上传)』,不得省略去向;有大小必须写大小。"
"【总次数口径】汇总『共N次访问/进行了N次』时,标注了(连接心跳)的ws./wss.等心跳域名【不计入】——总次数=各非心跳域名次数之和;心跳域名如需提及,单独表述为『另有WebSocket心跳连接』;严禁把心跳请求数加进总访问次数(2026-08-26高贯飞案例: 把心跳桶count加总成'1426次访问')。\n"
    "【数字精度铁律】explanation中的所有数字(次数/人数/天数/文件数/大小)必须与行为序列中标注的完全一致——窗口标注×13次你必须写13次,不得四舍五入/模糊化/写'多次'。当日累计N次须标注'今日累计N次'。引用行为史数据须标注'(近7天)'。"
    "【说明时间铁律】explanation描述的必须是【当前窗口】内发生的行为——日期与时段一律以当前窗口时间为准。风险记忆/行为史里的历史行为严禁写成本次说明的主体(禁止『某旧日期凌晨发送了N个文件』式主句,那是别的窗口的事);历史背景只能以'(近7天累计N次/活跃N天)'格式附带一句(2026-08-26展佳案例: 说明写08-20凌晨行为,当前窗口实为08-26,时间与说明对不上)。"
    "禁止泛泛套话,对象必须是具体文件名/域名, "
    "channels(数组,取自 usb|netdisk|personal_email|upload|local|remote_control)。"
"【追问工具——信息不足时可主动查询】当你觉得当前窗口信息不够判断时,不要猜,输出工具调用JSON:\n"
"  {\"tool\": \"emp_history\", \"args\": {}} — 查该员工近7天行为史(外发/招聘/删除等)\n"
"  {\"tool\": \"domain_global\", \"args\": {}} — 查窗口内风险域名的全公司使用情况\n"
"  {\"tool\": \"file_trace\", \"args\": {}} — 查窗口内外发文件在全公司的流转记录\n"
"工具返回后你可以继续调用其他工具或直接输出最终研判JSON。最多追问2次。\n"
    "\n【跨源上下文工具——看清完整故事线】"
    "\n  {'tool\": \"nearby_activity\", \"args\": {}} — 查该员工窗口前后30分钟的全部行为时间线(含深信服浏览+IPG文档+搜索,跨源故事线)——判断上下文因果"
    "\n  {'tool\": \"cross_source_dest\", \"args\": {}} — 当SEND/UPLOAD目的地未记录时,查深信服日志同时刻浏览的域名,推断文件去向\n"

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
        cat_tag = f"[{str(info['cat']).replace(chr(91),'').replace(chr(93),'')}]" if info["cat"] else ""
        # 浏览器标签标题(2026-08-20): IPG的APP_TITLE是页面内容语义——招聘站标题
        # 含"简历/人才"多为HR筛选,含职位名/薪资多为看JD;仅风险类域名,控token
        _tset = set()
        for e in window:
            if e.category == "WEB" and d in ((e.raw or {}).get("domain") or ""):
                _tset.update((e.raw or {}).get("titles") or [])
                _t1 = (e.raw or {}).get("title") or ""
                if _t1:
                    _tset.add(_t1)
        _titles = [t for t in _tset if t and t != "-"][:2]
        title_tag = f" 《{'》/《'.join(t[:28] for t in _titles)}》" if _titles else ""
        # 外发通道类域名附带URL路径样本(3个):让AI区分"打开页面/轮询"vs"真实上传/发送"
        path_hint = ""
        if rc and ("文件" in rc or "微信" in rc or "网盘" in rc or "邮箱" in rc):
            paths = list({u for e in window
                          if e.category == "WEB" and d in ((e.raw or {}).get("domain") or "")
                          for u in ((e.raw or {}).get("url_samples") or [])})[:3]
            if paths:
                path_hint = " 路径样本:" + " | ".join(paths)
        _app_name = ((window[0].raw or {}).get("app") or "").lower() if window else ""
        _app_src = " [微信内]" if "weixin" in _app_name or "wechat" in _app_name else (" [Office内]" if any(k in _app_name for k in ("word", "excel", "powerpnt")) else "")
        lines.append(f"[⚠{rc}] {d} {_cnt_tag(d, info['count'])} {cat_tag}{title_tag}{_app_src}{path_hint}")
    # 低信号(个人邮箱/微信)：标注但明确"访问≠外发"，避免被当高危
    for d, info in low_sig[:8]:
        rc = dicts.risk_class(d)
        cat_tag = f"[{str(info['cat']).replace(chr(91),'').replace(chr(93),'')}]" if info["cat"] else ""
        lines.append(f"[{rc}-低信号·访问非外发] {d} {_cnt_tag(d, info['count'])} {cat_tag}")
    n_other = len(others)
    # 文档/搜索事件前置(2026-08-24): SEND/UPLOAD是窗口的核心信号,排在常规网页
    # 噪声之前,保证AI第一屏看到真信号
    for e in others[:25]:
        t = e.occurred_at.strftime("%m-%d %H:%M")
        src = SRC.get(getattr(e, 'source', ''), '')
        if e.category == "SEARCH":
            lines.append(f"{t} [{src}] [搜索] \"{e.target_value}\"")
        else:
            _dp = (e.raw or {}).get("dest_path") or ""
            if _dp.startswith(("http:", "https:")):  # URL型目的地取主机名(srui案例: 整条URL太长且AI只抄前缀)
                _pp = _dp.split("/")
                _dp = _pp[2] if len(_pp) > 2 else _dp
            # 2026-08-26 srui案例: 说明只剩"通过网络发送"——输入行缺大小、dest空时不标注,
            # AI无从写具体;补大小与目的地缺失标注
            _sz = f", {e.size_bytes / 1048576:.1f}MB" if (e.size_bytes or 0) > 10240 else ""
            _dest = f" → {_dp[:60]}" if _dp and e.action in ("SEND", "UPLOAD", "PRINT") else (" → 目的地未记录(网页上传)" if e.action in ("SEND", "UPLOAD") else "")
            # 方向标记(2026-08-26高聪案例: 说明把"下载缩略图"定性为外发对象——
            # 下载/接收是数据进入本机,方向为收,不是外发证据)
            _dir = "↑发" if e.action in ("SEND", "UPLOAD", "PRINT", "BURN") else ("↓收" if e.action in ("DOWNLOAD", "RECV") else "  ")
            lines.append(f"{t} [{src}] [{e.action}{_dir}] {e.target_value}{_sz}（通道={(e.raw or {}).get('channel')}, 应用={(e.raw or {}).get('app')}）{_dest}")
    if n_other > 25:
        lines.append(f"…及另外 {n_other - 25} 条文档/搜索")
    # 常规访问压缩(2026-08-24欧阳清案例: 17个微软遥测/CDN噪声铺满15行,把唯一的
    # 真信号(微信SEND)挤到最后,稀释AI注意力)——常规域名仅列Top5,其余一行带过
    for d, info in normal[:10]:
        cat_tag = f"[{str(info['cat']).replace(chr(91),'').replace(chr(93),'')}]" if info["cat"] else ""
        lines.append(f"[访问网页] {d} ×{info['count']} {cat_tag}")
    if len(normal) > 10:
        lines.append(f"…及另外 {len(normal) - 10} 个常规域名访问（微软/CDN/搜索等服务流量，均非高风险，勿逐条分析）")

    raw = "\n".join(lines) if lines else "(无行为)"
    # 截断上限 3500 字(2026-08-26用户要求: 本地AI不费钱,保证完整输入不截断丢风险;
    # 旧版1500字截断导致高活跃员工窗口丢证据。超长时由pipeline切分为子窗口分次研判,
    # 此处只是最后兜底)
    if len(raw) > 3500:
        raw = raw[:3500] + "\n…（行为过多,pipeline将切分研判）"
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
    return [left, right]


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
            # IPG接入前闸门收紧(2026-08-20): 普通本地写(SAVE/MODIFY/RENAME等每人
            # 每天海量)不单独触发,只有真实外发信号才触发——UPLOAD/SEND/PRINT/BURN
            # (上传/发送/打印/刻录)或非本地通道(USB/网盘);文件名是否敏感由AI判断
            if e.action in ("UPLOAD", "SEND", "PRINT", "BURN"):
                return True
            if is_noise_doc(e):
                continue  # 系统/程序目录=程序自写,不算行为证据
            ch = (e.raw or {}).get("channel")
            if ch and ch != "LOCAL":
                return True
        if e.category == "SEARCH":
            # 搜索词语义(求职/数据带出/正常)交AI判断,不做关键词触发(2026-08-20
            # 用户口径;IPG搜索量低,全量送判可承受)
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


def _run_judge_tool(name: str, window, emp: str) -> str:
    """执行研判AI的追问工具,返回文本上下文(2026-08-26)。"""
    from db import Session, EventRow, bj_now
    from datetime import timedelta as _td
    s = Session()
    try:
        if name == "emp_history":
            evs = s.query(EventRow).filter(
                EventRow.employee_id == emp,
                EventRow.occurred_at >= bj_now() - _td(days=7)).all()
            from collections import Counter as _C2
            doms = _C2()
            sends = _C2()
            for e in evs:
                if e.category == "WEB":
                    d = ((e.raw or {}).get("domain") or "").lower()
                    rc = dicts.risk_class(d)
                    if rc:
                        doms[f"{rc}:{d[:30]}"] += e.count or 1
                elif e.category == "DOC" and e.action in ("SEND", "UPLOAD"):
                    sends[(e.target_value or "")[:30]] += 1
            parts = []
            if doms:
                parts.append("近7天风险访问: " + "; ".join(f"{k}×{v}" for k, v in doms.most_common(8)))
            if sends:
                parts.append("近7天外发文件: " + "; ".join(f"{k}×{v}" for k, v in sends.most_common(6)))
            return "; ".join(parts) if parts else "近7天无风险行为记录"

        elif name == "domain_global":
            doms = list({((e.raw or {}).get("domain") or "").lower()
                         for e in window if e.category == "WEB"
                         and dicts.risk_class(((e.raw or {}).get("domain") or "").lower())})[:5]
            if not doms:
                return "窗口内无风险域名"
            parts = []
            for d in doms:
                users = s.query(EventRow.employee_id).filter(
                    EventRow.category == "WEB", EventRow.occurred_at >= bj_now() - _td(days=7)).all()
                # SQL LIKE 逐域查太慢,改为内存过滤
                cnt = sum(1 for u in users if d in str(u))
                parts.append(f"{d[:30]}: 约{cnt}人近7天访问过")
            return "; ".join(parts)

        elif name == "file_trace":
            files = list({(e.target_value or "")[:36]
                          for e in window if e.category == "DOC" and e.action in ("SEND", "UPLOAD")})[:3]
            if not files:
                return "窗口内无外发文件"
            parts = []
            for f in files:
                rows = s.query(EventRow.employee_id, EventRow.action).filter(
                    EventRow.category == "DOC",
                    EventRow.target_value.like(f"{f[:20]}%"),
                    EventRow.occurred_at >= bj_now() - _td(days=30)).limit(10).all()
                for r in rows:
                    parts.append(f"{f[:20]}: {r[0]}执行过{r[1]}")
            return "; ".join(parts[:6]) if parts else "这些文件近30天无其他人操作记录"

        elif name == "nearby_activity":
            _ws = window[0].occurred_at if window else bj_now()
            _t0n = _ws - _td(minutes=30)
            _t1n = (window[-1].occurred_at if len(window) > 1 else _ws) + _td(minutes=30)
            evs = s.query(EventRow).filter(
                EventRow.employee_id == emp,
                EventRow.occurred_at >= _t0n, EventRow.occurred_at <= _t1n).order_by(EventRow.occurred_at).all()
            if not evs:
                return "窗口前后30分钟无其他行为记录"
            _lines2 = []
            for e in evs:
                raw = e.raw or {}
                _tt = str(e.occurred_at)[11:16]
                if e.category == "WEB":
                    d = (raw.get("domain") or "").lower()
                    if d and not dicts.is_heartbeat(d) and not d.startswith(("ws.", "wss.", "statistic.", "tm.", "log.", "telemetry.")):
                        rc = dicts.risk_class(d)
                        if rc or len(_lines2) < 12:
                            _lines2.append(f"{_tt} 浏览:{d[:30]}" + (f"[{rc}]" if rc else ""))
                elif e.category == "DOC":
                    _sz2 = f" {e.size_bytes / 1048576:.1f}MB" if (e.size_bytes or 0) > 10240 else ""
                    _dh2 = dicts.dest_host(raw)
                    _lines2.append(f"{_tt} {e.action}:{(e.target_value or '')[:24]}{_sz2}" + (f"→{_dh2[:24]}" if _dh2 else ""))
                elif e.category == "SEARCH" and e.target_value:
                    _lines2.append(f"{_tt} 搜索:{e.target_value[:18]}")
            return " | ".join(_lines2[:18]) if _lines2 else "窗口前后30分钟无显著行为"

        elif name == "cross_source_dest":
            _sends3 = [e for e in window if e.category == "DOC" and e.action in ("SEND", "UPLOAD")
                       and not dicts.dest_host(e.raw or {})]
            if not _sends3:
                return "所有SEND均有目的地记录,无需推断"
            _webs3 = s.query(EventRow).filter(
                EventRow.employee_id == emp, EventRow.category == "WEB",
                EventRow.occurred_at >= bj_now() - _td(hours=2)).all()
            _wmap = {}
            for w3 in _webs3:
                d = ((w3.raw or {}).get("domain") or "").lower()
                if d:
                    _wmap.setdefault(d, []).append(w3.occurred_at)
            _wl3 = [x.lower() for x in (dicts.get("risk_whitelist_domains") or [])]
            _results3 = []
            for se in _sends3:
                _near3 = sorted({d for d, ts3 in _wmap.items()
                                 if any(abs((t3 - se.occurred_at).total_seconds()) <= 300 for t3 in ts3)
                                 and not d.startswith(("ws.", "statistic.", "tm.", "log."))})[:3]
                _wl_hit3 = any(any(d == x or d.endswith("." + x) for x in _wl3) for d in _near3)
                if _wl_hit3:
                    _results3.append(f"{(se.target_value or '')[:22]}→同时刻浏览为公司白名单通道(Teams/M365等)")
                elif _near3:
                    _results3.append(f"{(se.target_value or '')[:22]}→同时刻浏览{'/'.join(_near3[:2])}(非白名单)")
                else:
                    _results3.append(f"{(se.target_value or '')[:22]}→±5分钟无深信服浏览记录")
            return "; ".join(_results3[:5])

        return f"未知工具: {name}"
    finally:
        s.close()


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
    try:
        from riskmemory import memory_for_llm
        _mem = memory_for_llm(window[0].employee_id if window else "")
    except Exception:
        _mem = ""
    # 源头注入深信服目的地(2026-08-26用户要求: 准确性>及时性,不等AI追问——
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
                    _dest_hint = f"\n【深信服目的地推断】上传时刻±10分钟浏览: {', '.join(_hints)}\n(据此判断文件去向;白名单通道=正常办公)"
            finally:
                _s2.close()
        except Exception:
            pass

    user = (f"员工：{window[0].employee_id}（设备：{window[0].employee_id}）\n"
            f"写explanation时:域名次数优先『本窗口N次,今日累计M次』双口径(今日累计仅当序列标注了[当日累计]才可引用,未标注就只写窗口次数,严禁编造累计)。请输出 JSON。")
    try:
        # 工具循环(2026-08-26用户要求: AI信息不足时可主动查询关联日志再分析,
        # 最多追问2轮,防止无限循环)
        _msgs = [{"role": "system", "content": SYSTEM_PROMPT},
                 {"role": "user", "content": user}]
        raw = ""
        for _round in range(3):
            raw = llm_client.chat(_msgs, max_tokens=800, timeout=120, model=model)
            import re as _re4
            _txt = llm_client.strip_think(raw)
            _m2 = _re4.search(r'"tool":\s*"(\w+)"', _txt)
            if not _m2 or _m2.group(1) not in ("emp_history", "domain_global", "file_trace"):
                break
            _tresult = _run_judge_tool(_m2.group(1), window, window[0].employee_id if window else "")
            _msgs.append({"role": "assistant", "content": _txt[:300]})
            _msgs.append({"role": "user", "content": "工具[" + _m2.group(1) + "]返回: " + _tresult[:800] + " 请基于补充信息给出最终研判JSON。"})
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
