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
    ],
    "recruitment_sites": [
        "zhaopin.com", "51job.com", "51job.cn", "lagou.com", "zhipin.com", "liepin.com",
        "boss.com", "bosszhipin", "zhilian", "jobcn.com", "51zhaopin", "linkedin.com",
        "maimai.cn", "kanzhun.com", "chinahr.com", "yingjiesheng.com", "dajie.com",
        "indeed.com", "glassdoor", "nowcoder.com", "xiaoyuan", "zhaopin.baidu",
        "jobui.com", "tianji", "fesco", "fescoadecco", "zhipin", "zhaopin",
    ],
    "netdisk_domains": [
        "pan.baidu.com", "eyun.baidu.com", "alipan.com", "aliyundrive.com", "weiyun.qq.com",
        "jianguoyun.com", "onedrive.live.com", "dropbox.com", "115.com", "lanzou.com",
        "lanzoux", "pan.xunlei.com", "cloud.189.cn", "yun.139.com", "pan.quark.cn",
    ],
    "personal_email_domains": [
        "mail.qq.com", "mail.163.com", "mail.126.com", "gmail.com", "outlook.live.com",
        "mail.sina.com.cn", "mail.sohu.com", "mail.10086.cn", "mail.139.com",
        "mail.aliyun.com", "foxmail.com", "mail.yahoo.com",
    ],
    "job_search_terms": [
        "简历", "招聘", "跳槽", "求职", "offer", "待遇", "工资", "薪酬", "猎头",
        "面试", "竞业", "竞对", "竞争对手",
    ],
    "risk_search_terms": [
        "网盘", "数据恢复", "匿名", "匿名邮箱", "临时邮箱", "绕过", "外发", "解密",
        "破解", "泄密", "u盘启动", "文件恢复", "截图", "窃取",
    ],
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
    """取一个字典（带进程内缓存）。"""
    _ensure()
    if name in _cache:
        return _cache[name]
    s = Session()
    try:
        d = s.query(DictRow).filter_by(name=name).first()
        vals = d.payload if d else DEFAULTS.get(name, [])
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
    _ensure()
    s = Session()
    try:
        out = {}
        for name in DEFAULTS:
            d = s.query(DictRow).filter_by(name=name).first()
            out[name] = d.payload if d else DEFAULTS[name]
        return out
    finally:
        s.close()


# ---------------- 应用配置（key-value）----------------

def get_setting(key: str, default=None):
    init_db()
    s = Session()
    try:
        r = s.query(SettingRow).filter_by(key=key).first()
        return r.value if r else default
    finally:
        s.close()


def set_setting(key: str, value):
    init_db()
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
    """返回 [(中文标签, [域名子串...])]：当前生效的高风险域名模式。"""
    return [
        ("远程控制", ["todesk", "teamviewer", "anydesk", "向日葵", "sunlogin", "rustdesk", "vnc"]),
        ("VPN/翻墙", ["privado", "clash", "clashverge", "shadowsocks", "v2ray", "trojan", "wireguard", "nordvpn", "expressvpn", "surfshark", "psiphon", "vmess", " Lantern"]),
        ("代码外发", ["github", "gitlab", "gitee.com", "bitbucket", "gitpush", "coding.net"]),
        ("网盘/云盘", list(get("netdisk_domains"))),                  # 公司禁止
        ("个人邮箱", list(get("personal_email_domains"))),            # 公司禁止
        ("招聘求职", list(get("recruitment_sites"))),
        ("微信文件助手", ["filehelper", "file.qq.com", "传输助手", "filehelper.weixin"]),  # 微信传文件=外发;普通微信访问不算
    ]


def risk_class(domain: str):
    """域名 → 高风险类别中文标签（如"远程控制"/"网盘/云盘"）；非高风险返回 None。"""
    d = (domain or "").lower()
    if not d:
        return None
    for label, pats in risk_patterns():
        for p in pats:
            if p and p.lower() in d:
                return label
    return None


# 类别 → 信号强度（仅"上网行为日志"视角）。
# 公司策略: 个人邮箱/网盘【禁止使用】→访问即违规(high); 微信文件助手=传文件外发嫌疑(high);
# 普通微信访问=正常办公(不入此表); 远程控制降为mid(工具使用,凌晨/密集才告警); 招聘=job。
RISK_TIER = {
    "远程控制": "mid",           # 工具使用(降权,凌晨/密集才告警)
    "VPN/翻墙": "high",          # 翻墙=违规+绕监控,访问即告警
    "代码外发": "mid",           # 代码仓库上传嫌疑,凌晨/密集才告警
    "网盘/云盘": "high",         # 公司禁止→访问即违规告警
    "个人邮箱": "high",          # 公司禁止→访问即违规告警
    "招聘求职": "job",           # 求职意图
    "微信文件助手": "high",      # 微信传文件=外发嫌疑(普通微信访问不算)
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
_SLACK_SDK_HINT = ("api.", "sdk", "audid", "fourier", "nbsdk", "log.", "error.",
                   "cloud.video", "stat.", "analytics.", "monitor.", "ping.", "collector")


def slack_category(domain: str):
    """域名 → 摸鱼类别(视频/社交/购物/资讯/音乐);排除SDK埋点;非摸鱼返回 None。
    摸鱼域名存 DB DictRow(slack_domains, object{cat:[domains]}),可后台/AI动态更新。"""
    d = (domain or "").lower()
    if not d or any(d.startswith(h) or h in d for h in _SLACK_SDK_HINT):
        return None
    cats = get("slack_domains")
    if not isinstance(cats, dict):
        return None
    for cat, doms in cats.items():
        for dom in (doms or []):
            if d == dom or d.endswith("." + dom):
                return cat
    return None
