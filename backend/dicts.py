"""字典与应用配置：DB 持久化，检测器/解析器运行时读取（可由后台界面增删改）。

字典：sensitive_keywords / recruitment_sites / netdisk_domains /
      personal_email_domains / job_search_terms / risk_search_terms
配置(key-value)：llm_base_url / llm_api_key / llm_model / syslog_* 等。
"""
from __future__ import annotations

from db import DictRow, Session, SettingRow, init_db

DEFAULTS = {
    "sensitive_keywords": [
        "客户", "名单", "合同", "报价", "标书", "财务", "源码", "设计图", "设计",
        "申报", "简历", "MSA", "秘书公司", "薪酬", "工资", "护照", "签证", "专利",
        "密码", "账套", "报表", "离职",
        # 2026-08-20 R1文档深扫建议: 公司项目编号前缀特征
        "WX-RPT", "WX-AMP", "MQR", "HX-RPT", "试验用药品", "药物警戒",
    ],
    "recruitment_sites": [
        "zhaopin.com", "51job.com", "51job.cn", "lagou.com", "zhipin.com", "liepin.com",
        "boss.com", "bosszhipin", "zhilian", "jobcn.com", "51zhaopin",
        "maimai.cn", "kanzhun.com", "chinahr.com", "yingjiesheng.com", "dajie.com",
        "indeed.com", "glassdoor", "nowcoder.com", "xiaoyuan", "zhaopin.baidu",
        "jobui.com", "tianji", "fesco", "fescoadecco", "zhipin", "zhaopin", "sndhr.com",
        # linkedin(领英)/hrss.suzhou(苏州人才网)已移除: 2026-08-20用户确认属正常业务行为,不算离职求职
    ],
    "netdisk_domains": [
        "pan.baidu.com", "eyun.baidu.com", "alipan.com", "aliyundrive.com", "weiyun.qq.com",
        "jianguoyun.com", "dropbox.com", "115.com", "lanzou.com",
        "lanzoux", "pan.xunlei.com", "cloud.189.cn", "yun.139.com", "pan.quark.cn",
        "smallpdf.com", "wetransfer.com", "cowtransfer.com", "filemail.com",  # 网页文件中转/上传工具=外发通道(2026-08-20)
        # onedrive.live.com 移除: OneDrive是公司采购的M365组件(2026-08-19用户确认),
        # 全家域名走 risk_whitelist_domains 豁免
    ],
    "personal_email_domains": [
        # outlook.live.com 移除(2026-08-28用户确认): 公司邮箱网页版就是这个地址,
        # 不是个人邮箱——走 risk_whitelist_domains 豁免,曾致多名员工误报policy_violation
        "mail.qq.com", "mail.163.com", "mail.126.com", "gmail.com",
        "mail.sina.com.cn", "mail.sohu.com", "mail.10086.cn", "mail.139.com",
        "mail.aliyun.com", "foxmail.com", "mail.yahoo.com",
    ],
    "job_search_terms": [
        "简历", "招聘", "跳槽", "求职", "offer", "待遇", "工资", "薪酬", "猎头",
        "面试", "竞业", "竞对", "竞争对手",
        # 2026-08-20扩充(IPG搜索词已可用): 离职流程类前兆词
        "离职证明", "简历模板", "社保转移", "公积金提取", "年终奖发放时间", "试用期辞职",
        "背调", "工资流水", "竞业限制赔偿",
    ],
    "risk_search_terms": [
        "网盘", "数据恢复", "匿名", "匿名邮箱", "临时邮箱", "绕过", "外发", "解密",
        "破解", "泄密", "u盘启动", "文件恢复", "截图", "窃取",
        # 2026-08-20扩充: 数据带出/规避审计类
        "批量导出", "客户名单", "数据导出", "文件加密发送", "无痕模式", "隐私窗口",
    ],
    "slack_whitelist_domains": [],   # 摸鱼豁免白名单:公司业务需要访问的娱乐类站(命中不算摸鱼)
    "risk_whitelist_domains": [   # 风险豁免白名单:公司采购的正规网盘/企业邮箱等(命中不进风险识别)
        # OneDrive全家=M365公司组件(2026-08-19用户确认"OneDrive是公司的"):
        # 同步流量域storage.live.com曾漏判审查被误加禁止字典,已纠正;张雪凌晨OneDrive告警属误判
        "storage.live.com", "onedrive.live.com", "my.microsoftpersonalcontent.com",
        "xft.cmbchina.com",  # 公司OA/费控平台(2026-08-21用户确认): 发票/报销文件发送属正常业务
        # Teams/M365企业通道(2026-08-21用户确认Teams是公司办公软件): 企业邮箱发附件/Teams共享不算外发
        "teams.cloud.microsoft", "teams.microsoft.com", "outlook.cloud.microsoft",
        "smtp.office365.com", "outlook.office365.com", "outlook.office.com",
        # 公司邮箱网页版(2026-08-28用户确认): outlook.live.com不是个人邮箱,是本公司
        # 邮箱网页版地址;login.live.com为其登录跳转域。邻近上传推断(±180s)依赖本白名单
        "outlook.live.com", "login.live.com",
        # 公司内部平台(2026-08-24): ELN电子实验记录本/Certara仿真租户/公司M365租户SharePoint
        "eln.huashen.bio", "huashen.certara.net",
        "helixoncn.sharepoint.com", "helixoncn-my.sharepoint.com",
        # M365基础设施域(2026-08-24鄢荣梅案例): *.sharepoint.net=微软后端遥测/AAD,
        # cloud.microsoft=M365全家(teams./m365./*.svc.)——网页上传邻近推断依赖
        "sharepoint.net", "cloud.microsoft", "onenote.com", "sharepointonline.com",
        # 公司自有主域(2026-08-26金燕萍案例: lab.huashen.bio被当第三方外发——枚举子域永远漏,
        # 匹配器是后缀通配,挂主域即全子域生效: eln/lab/sftp/helixon集群等一律内部)
        "huashen.bio", "helixon.com", "filez.com",  # FileZ公司网盘(客户端zbox,服务器fs.huashen.bio;IPG记www.filez.com为云端路径,2026-08-26管理员确认)
    ],
    "slack_sdk_domains": [],         # 心跳/埋点排除域名:客户端挂后台的规律上报,不算摸鱼(AI扫描建议+人工采纳维护)
    "slack_domains": {
        "视频": ["bilibili.com", "douyin.com", "iesdouyin.com", "snssdk.com", "kuaishou.com",
                "youku.com", "iqiyi.com", "mgtv.cn", "youtube.com", "fun.tv"],
        "社交": ["weibo.com", "weibo.cn", "douban.com", "doubanio.com", "xiaohongshu.com",
                "zhihu.com", "tieba.baidu.com", "hupu.com", "reddit.com"],
        "购物": ["taobao.com", "tmall.com", "jd.com", "jd.hk", "pdd.com", "yangkeduo.com",
                "suning.com", "vip.com", "smzdm.com"],
        "资讯": ["toutiao.com", "36kr.com", "ifeng.com", "sspai.com"],
        "音乐": ["music.163.com", "y.qq.com", "kugou.com", "kuwo.cn", "spotify.com", "music.apple.com"],
    },
    "work_domains": [
        "office.com", "outlook.com", "cloud.microsoft", "microsoftonline.com", "office365.com",
        "outlook.live.com", "login.live.com",  # 公司邮箱网页版及其登录域(2026-08-28用户确认)
        "sharepoint.com", "onedrive.com", "azure.com",
        "bing.com", "baidu.com", "google.com", "so.com", "sogou.com",
        "cmbchina.com", "icbc.com.cn", "ccb.com", "boc.cn", "abchina.com", "unionpay.com",
        "gov.cn", "youdao.com", "wps.cn", "notion.so", "feishu.cn", "dingtalk.com", "larksuite.com",
        "helixon.com", "huashen.bio",
        "stackoverflow.com", "csdn.net", "juejin.cn", "npmjs.com", "pypi.org", "docker.com",
    ],
    # 以下 4 类原写死在 risk_patterns(),搬进字典使后台「字典」页可增删,
    # 新增远程工具/VPN/代码仓库无需改代码。AI规则建议也会覆盖这些类。
    "remote_control_domains": [
        "todesk", "teamviewer", "anydesk", "向日葵", "sunlogin", "rustdesk", "vnc",
    ],
    "vpn_domains": [
        "privado", "clash", "clashverge", "shadowsocks", "v2ray", "trojan", "wireguard",
        "nordvpn", "expressvpn", "surfshark", "psiphon", "vmess", "lantern",
    ],
    "code_repo_domains": [
        "github", "gitlab.com", "gitee.com", "bitbucket.org", "coding.net",
    ],
    "wechat_file_domains": [
        "filehelper", "传输助手", "filehelper.weixin",
    ],
    # AI 助手(ChatGPT/DeepSeek/豆包/Kimi/千问/Copilot 等)。
    # 风险=数据外发(往 AI 塞公司数据),不是访问本身。设为 mid 档:不访问即触发,
    # 但只有凌晨/密集才告警(工作时段正常使用 AI 不打扰),由研判 AI 结合上下文判断。
    "ai_assistant_domains": [
        "chatgpt.com", "openai.com", "oaistatic.com", "chatgpt-sidebar.com",
        "claude.ai", "anthropic.com",
        "gemini.google.com", "aistudio.google.com", "bard.google.com",
        "deepseek.com", "chat.deepseek.com",
        "doubao.com", "kimi.com", "moonshot.cn",
        "qianwen.com", "tongyi.com", "aliyundashscope",
        "zhipu.ai", "z.ai", "chatglm.cn", "bigmodel.cn",
        "yiyan.baidu.com", "baichuan-ai",
        "yuanbao.tencent.com", "hunyuan",
        "metaso.cn", "perplexity.ai", "poe.com",
        "githubcopilot.com", "copilot.microsoft", "copilot.tencent.com",
    ],
}

_inited = False
_cache: dict = {}


def _copy_val(vals):
    """list 浅拷贝; dict 原样返回(dict-typed 如 slack_domains 不能 list() 否则只剩 keys)。"""
    return vals if isinstance(vals, dict) else list(vals)


def _ensure():
    global _inited
    if _inited:
        return
    init_db()
    s = Session()
    try:
        for name, vals in DEFAULTS.items():
            d = s.query(DictRow).filter_by(name=name).first()
            if not d:
                s.add(DictRow(name=name, payload=_copy_val(vals)))
            elif isinstance(vals, dict) and not isinstance(d.payload, dict):
                d.payload = _copy_val(vals)  # 旧bug曾把dict灌成list(只剩keys), 自动修复
        s.commit()
        _inited = True
    finally:
        s.close()


def get(name: str) -> list:
    """取一个字典（带进程内缓存）。
    合并策略(2026-08-20): 源码DEFAULTS为底 + DB行只追加增量——此前DB快照整体
    覆盖DEFAULTS,源码新增域名(sndhr/hrss/OneDrive豁免)连续两次静默失效。
    用户在字典管理页添加的条目(DB有、DEFAULTS无)照常生效。"""
    _ensure()
    if name in _cache:
        return _cache[name]
    base = DEFAULTS.get(name, [])
    s = Session()
    try:
        d = s.query(DictRow).filter_by(name=name).first()
        if isinstance(base, dict):
            vals = dict(base)
            if d and isinstance(d.payload, dict):
                vals.update({k: v for k, v in d.payload.items() if k not in vals})
        else:
            extra = [x for x in ((d.payload if d else None) or []) if x not in base]
            vals = list(base) + extra
        _cache[name] = vals
        return vals
    finally:
        s.close()


def set_dict(name: str, vals) -> None:
    _ensure()
    s = Session()
    try:
        d = s.query(DictRow).filter_by(name=name).first()
        payload = _copy_val(vals)
        if d:
            d.payload = payload
        else:
            s.add(DictRow(name=name, payload=payload))
        s.commit()
    finally:
        s.close()
    _cache.pop(name, None)  # 失效缓存，下次 get 重新读


def all_dicts() -> dict:
    """字典页展示口径(2026-08-24修复): 返回DEFAULTS+DB合并后的生效视图。
    旧版只回DB原始行——白名单实际生效15+个域名,页面只显示用户手动加的3个,
    严重误导(用户以为白名单几乎是空的)。与get()同源,保存时整体落库不丢默认项。"""
    _ensure()
    return {name: get(name) for name in DEFAULTS}


# ---------------- 应用配置（key-value）----------------

_db_ready = False


def _init_once():
    """init_db 只跑一次。旧版 get/set_setting 每次都 create_all(拿连接做 DDL 检查),
    在 NullPool+syslog 写库竞争下慢到秒级,改密等多次调用的接口会超时。"""
    global _db_ready
    if not _db_ready:
        init_db()
        _db_ready = True


def get_setting(key: str, default=None):
    _init_once()
    s = Session()
    try:
        r = s.query(SettingRow).filter_by(key=key).first()
        return r.value if r else default
    finally:
        s.close()


def set_setting(key: str, value):
    _init_once()
    s = Session()
    try:
        r = s.query(SettingRow).filter_by(key=key).first()
        if r:
            r.value = value
        else:
            s.add(SettingRow(key=key, value=value))
        s.commit()
    finally:
        s.close()


# ---------------- 域名风险分级（触发门 / 窗口格式化 / prompt 共用）----------------
# 注：深信服 app 字段是"行业分类"（IT/银行/新闻…），不含风险语义，
# 真正的高危信号靠"域名"识别（todesk 被归到 IT行业 里，但域名能认出）。

def risk_patterns() -> list:
    """返回 [(中文标签, [域名子串...])]：当前生效的高风险域名模式。
    全部走 DB 字典(后台「字典」页可增删),新增远程工具/网盘等无需改代码。
    注: VPN/翻墙经业务确认不算违规(2026-08-13),从风险识别移除——
    vpn_domains 字典保留(以后要恢复只需把下面这行加回 + 改 RISK_TIER)。"""
    return [
        ("远程控制", list(get("remote_control_domains"))),
        # ("VPN/翻墙", list(get("vpn_domains"))),  # 业务规则:翻墙不算违规,不再识别/告警
        ("代码外发", list(get("code_repo_domains"))),    # github子串覆盖github.io等
        ("网盘/云盘", list(get("netdisk_domains"))),       # 公司禁止
        ("个人邮箱", list(get("personal_email_domains"))), # 公司禁止
        ("招聘求职", list(get("recruitment_sites"))),
        ("微信文件助手", list(get("wechat_file_domains"))),  # 微信传文件=外发
        ("AI助手", list(get("ai_assistant_domains"))),       # 往AI塞数据=外发嫌疑,mid档
    ]


def _match_domain(domain: str, pat: str) -> bool:
    """域名匹配：含点的模式按域名后缀匹配(d==p 或 d 以 "."+p 结尾)，避免
    mail.qq.com 误伤 exmail.qq.com(企业邮箱)、linkedin.com 误伤
    linkedin.com.cdn.cloudflare.net(CDN)等子串误命中；无点的关键词仍用
    子串匹配(todesk→authds.todesk.com、filehelper→szfilehelper.weixin.qq.com、
    github→github.io)。"""
    if not pat:
        return False
    p = pat.lower()
    if "." in p:
        return domain == p or domain.endswith("." + p)
    return p in domain


def dest_host(raw: dict) -> str:
    """DOC事件目的地主机名(2026-08-24统一): URL型(https://x/y)取host,
    普通取首段,空返回''。此前各模块各自split('/')[0],URL只剩'https:'。"""
    d = ((raw or {}).get("dest_path") or "").strip().lower()
    if d.startswith(("http:", "https:")):
        p2 = d.split("/")
        d = p2[2] if len(p2) > 2 else d
    else:
        d = d.split("/")[0]
    if ":" in d:  # 剥端口(eln.huashen.bio:5083 → eln.huashen.bio,2026-08-24白名单匹配被端口挡)
        d = d.split(":")[0]
    return d


def whitelisted_dest(raw: dict, webs=None, ts=None) -> bool:
    """外发目的地在公司白名单。空目的地(网页上传IPG不记域名)时,若给了webs
    [(时间,域名)]则按±3分钟推断(Teams/M365传附件不算外发)。"""
    d = dest_host(raw)
    # 私网IP目的地(2026-08-26胡峰案例: 3.5GB"外发"实为传往10.4.128.9=IPG服务器自身通道)
    # ——内网传输不构成数据外发
    _pp = d.split(".")
    if len(_pp) == 4 and all(x.isdigit() for x in _pp):
        _a, _b2 = int(_pp[0]), int(_pp[1])
        if _a == 10 or _a == 127 or (_a == 192 and _b2 == 168) or (_a == 172 and 16 <= _b2 <= 31):
            return True
    wl = [w.lower() for w in (get("risk_whitelist_domains") or [])]
    if d:
        return any(d == w or d.endswith("." + w) for w in wl)
    if webs and ts is not None:
        for t, dm in webs:
            if abs((t - ts).total_seconds()) <= 180 and                     any(dm == w or dm.endswith("." + w) for w in wl):
                return True
    return False


def risk_class(domain: str):
    """域名 → 高风险类别中文标签（如"远程控制"/"网盘/云盘"）；非高风险返回 None。
    白名单 risk_whitelist_domains 命中直接豁免(公司采购的正规网盘/企业邮箱等)。"""
    d = (domain or "").lower()
    if not d:
        return None
    for dom in get("risk_whitelist_domains") or []:
        if d == dom or d.endswith("." + dom):
            return None
    for label, pats in risk_patterns():
        for p in pats:
            if _match_domain(d, p):
                return label
    return None


# 类别 → 信号强度（仅"上网行为日志"视角）。
# 公司策略: 个人邮箱/网盘【禁止使用】→访问即违规(high); 微信文件助手=传文件外发嫌疑(high);
# 普通微信访问=正常办公(不入此表); 远程控制降为mid(工具使用,凌晨/密集才告警); 招聘=job。
RISK_TIER = {
    "远程控制": "mid",           # 工具使用(降权,凌晨/密集才告警)
    # "VPN/翻墙" 已移除(业务规则:翻墙不算违规,不再告警)
    "代码外发": "mid",           # 代码仓库上传嫌疑,凌晨/密集才告警
    "网盘/云盘": "high",         # 公司禁止→访问即违规告警
    "个人邮箱": "high",          # 公司禁止→访问即违规告警
    "招聘求职": "job",           # 求职意图
    "微信文件助手": "high",      # 微信传文件=外发嫌疑(普通微信访问不算)
    "AI助手": "mid",             # 往AI塞数据=外发嫌疑,降权(工作时段正常用,凌晨/密集才告警)
}


def risk_tier(domain: str):
    """域名 → 信号强度 high/mid/low/job；非高危域名返回 None。

    should_trigger / 评分锚点 / 兜底 共用：high/mid 才算外发信号，
    low(邮箱/微信)单独不触发、不加分。"""
    rc = risk_class(domain)
    return RISK_TIER.get(rc) if rc else None


# 远程控制工具的"客户端认证/心跳"子域(如 authds.todesk.com)——是软件后台定期连认证服务器,
# 不是员工主动发起的远程控制/外发。should_trigger 里忽略这类事件,避免凌晨心跳被误判为"员工非工作时段高危行为"。
def is_heartbeat(domain: str) -> bool:
    d = (domain or "").lower()
    if not d or risk_class(d) != "远程控制":
        return False
    first = d.split(".")[0]
    return first.startswith("auth") or "authds" in d


# 已知SDK埋点/统计/日志子域前缀(排除,避免把app后台请求算作主动摸鱼)
# 注:纯埋点/采集域名一律排除(挂后台心跳≠人在看);acs/api网关类不排除——
# 客户端刷内容也走网关,靠连段gap收紧+密度自然区分(埋点低频散布,真浏览密集)。
_SLACK_SDK_HINT = ("api.", "sdk", "audid", "fourier", "nbsdk", "log.", "error.", "err.", "perf.",
                   "mqtt.", "sugar.", "datahub.", "doubanio", "umdcv4", "cloudvideocdn", "rta",
                   "cloud.video", "stat.", "analytics.", "monitor.", "ping.", "collector",
                   "adashx", "amplitude", "applog", "umeng", "bugly", "sentry", "tongji",
                   "data-collect", "collect.", "beacon", "track.", "metrics.", "report.")

# 基础设施/CDN/连通性探测子域(任何分类标签下都不算摸鱼——是机器流量不是人在娱乐)
_SLACK_INFRA_HINT = ("cdn", "cds", "cache", "static", "assets", "geo", "connectivity", "smtcdns",
                     "xboxservices", "userconte", "cloudcache", "adobecces", "hypothes", "pendo",
                     "schemaapp", "id5-sync", "tls", "ocsp", "crl", "ntp", "diag")

# 深信服行业分类标签 → 摸鱼类别的映射规则(主识别通道):
# 覆盖率100%的专业分类库替代逐域名枚举字典;字典降级为"未识别兜底+细分补充"。
DEFAULT_SLACK_CLASS_RULES = {
    "pos": ["娱乐", "视频", "游戏", "购物", "音乐", "直播", "小说", "漫画", "体育", "电影", "短视频"],
    "neg": ["会议", "企业", "远程", "协助", "更新", "推送", "基础服务", "文件", "Outlook", "Teams",
            "skype", "Skype", "微信PC版", "网盘", "邮件", "代理", "管家", "同步"],
    "map": {"视频": "视频", "直播": "视频", "游戏": "游戏", "购物": "购物", "音乐": "音乐",
            "娱乐": "资讯", "体育": "资讯", "小说": "资讯", "漫画": "资讯", "电影": "视频", "短视频": "视频"},
}


def slack_category(domain: str, label: str = None):
    """域名+深信服分类标签 → 摸鱼类别;非摸鱼返回 None。

    识别优先级(2026-08-17 架构调整:分类库为主,字典为辅):
      1. 白名单 slack_whitelist_domains → 直接豁免(公司业务需要访问的娱乐站等)
      2. 基础设施/SDK 子域 → 排除(机器流量)
      3. 深信服行业分类标签命中规则(slack_class_rules) → 按标签归类【主通道】
      4. slack_domains 域名字典 → 兜底(标签缺失/未识别应用时)
    label = 报文里的网站分类(raw.category 或 raw.app),未知传 None 走字典兜底。"""
    d = (domain or "").lower()
    if not d or any(d.startswith(h) or h in d for h in _SLACK_SDK_HINT):
        return None
    for dom in get("slack_sdk_domains") or []:
        if d == dom or d.endswith("." + dom):
            return None
    for dom in get("slack_whitelist_domains") or []:
        if d == dom or d.endswith("." + dom):
            return None
    if d.split(".")[0] in _SLACK_INFRA_HINT or any(k in d for k in _SLACK_INFRA_HINT):
        return None
    lab = (label or "").strip()
    # 企业通讯排除(2026-08-21): 深信服把Teams/Skype/会议标成'网上聊天'——公司办公
    # 沟通不是摸鱼,在标签规则命中前排除(teams.cloud.microsoft 1295次/天误算案例)
    if lab and any(k in lab for k in ("Teams", "Skype", "会议", "企业微信")):
        return None
    if lab and lab != "-":
        rules = get("slack_class_rules") or DEFAULT_SLACK_CLASS_RULES
        if isinstance(rules, dict) and any(k in lab for k in rules.get("pos", [])) \
                and not any(k in lab for k in rules.get("neg", [])):
            for kw, cat in (rules.get("map") or {}).items():
                if kw in lab:
                    return cat
    cats = get("slack_domains")
    if not isinstance(cats, dict):
        return None
    for cat, doms in cats.items():
        for dom in (doms or []):
            if d == dom or d.endswith("." + dom):
                return cat
    return None


def work_category(domain: str):
    """域名 → 是否工作网站(办公/银行/政府/搜索/工具/公司业务);基于 work_domains 白名单。"""
    d = (domain or "").lower()
    if not d:
        return None
    for dom in get("work_domains"):
        if d == dom or d.endswith("." + dom):
            return "工作"
    return None
