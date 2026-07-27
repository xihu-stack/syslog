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
        "maimai.cn", "kanzhun.com",
    ],
    "netdisk_domains": [
        "pan.baidu.com", "eyun.baidu.com", "alipan.com", "aliyundrive.com", "weiyun.qq.com",
        "jianguoyun.com", "onedrive.live.com", "dropbox.com", "115.com", "lanzou.com",
        "lanzoux", "pan.xunlei.com", "cloud.189.cn", "yun.139.com", "pan.quark.cn",
    ],
    "personal_email_domains": [
        "mail.qq.com", "mail.163.com", "mail.126.com", "gmail.com", "outlook.live.com",
        "outlook.com", "mail.sina.com.cn", "mail.sohu.com", "mail.10086.cn", "mail.139.com",
        "mail.aliyun.com", "foxmail.com", "yahoo.com",
    ],
    "job_search_terms": [
        "简历", "招聘", "跳槽", "求职", "offer", "待遇", "工资", "薪酬", "猎头",
        "面试", "竞业", "竞对", "竞争对手",
    ],
    "risk_search_terms": [
        "网盘", "数据恢复", "匿名", "匿名邮箱", "临时邮箱", "绕过", "外发", "解密",
        "破解", "泄密", "u盘启动", "文件恢复", "截图", "窃取",
    ],
}

_inited = False
_cache: dict = {}


def _ensure():
    global _inited
    if _inited:
        return
    init_db()
    s = Session()
    try:
        for name, vals in DEFAULTS.items():
            if not s.query(DictRow).filter_by(name=name).first():
                s.add(DictRow(name=name, payload=list(vals)))
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


def set_dict(name: str, vals: list) -> None:
    _ensure()
    s = Session()
    try:
        d = s.query(DictRow).filter_by(name=name).first()
        if d:
            d.payload = list(vals)
        else:
            s.add(DictRow(name=name, payload=list(vals)))
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
        ("网盘/云盘", list(get("netdisk_domains"))),
        ("个人邮箱", list(get("personal_email_domains"))),
        ("招聘求职", list(get("recruitment_sites"))),
        ("微信传输", ["weixin.qq.com", "wx.qq.com", "wechat.com", "filehelper", "weixin", "work.weixin.qq"]),
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
