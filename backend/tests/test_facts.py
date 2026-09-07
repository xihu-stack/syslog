# -*- coding: utf-8 -*-
"""公司域名事实单源(2026-09-07盘点①): facts.py 是唯一文本源,
detector 研判prompt内嵌引用(零变化), domain_scan/daygate 外围通道注入。"""
import inspect


def test_facts_embedded_in_system_prompt():
    """detector.SYSTEM_PROMPT 必须整段包含 facts 常量——保证研判prompt
    用的是单源那份,没有私留副本(副本=口径漂移的起点)。"""
    import detector
    import facts
    assert facts.COMPANY_DOMAIN_FACTS in detector.SYSTEM_PROMPT


def test_facts_anchors():
    import facts
    for anchor in ("huashen.bio", "helixon.com", "outlook.live.com",
                   "xft.cmbchina.com", "onedrive.live.com", "storage.live.com"):
        assert anchor in facts.COMPANY_DOMAIN_FACTS, anchor


def test_scan_facts_cover_recruitment_side():
    """外围通道注入版含招聘侧公司确认事实(italent=北森HR系统,非求职站)。"""
    import facts
    for anchor in ("italent", "linkedin", "hrss.suzhou", "北森"):
        assert anchor in facts.SCAN_CALIBER_FACTS, anchor


def test_domain_scan_and_daygate_inject_facts():
    """两个外围AI通道的源码必须引用 SCAN_CALIBER_FACTS(注入接线不回退)。"""
    import domain_scan
    import daygate
    assert "SCAN_CALIBER_FACTS" in inspect.getsource(domain_scan)
    assert "SCAN_CALIBER_FACTS" in inspect.getsource(daygate)


def test_business_profile_single_source():
    """业务画像单源(2026-09-07盘点②): detector C04 条款就是 facts 常量本身
    (动态引用非字面副本), massops 批量删除分析接同一份。"""
    import detector
    import facts
    import massops
    c04 = [c for c in detector.CLAUSES if c["id"] == "C04"][0]
    assert c04["text"] is facts.BUSINESS_PROFILE_FACTS
    assert "BUSINESS_PROFILE_FACTS" in inspect.getsource(massops)
    for anchor in ("生物医药研发企业", "HX/HXN/CBL/DLL", "临床试验文件", "低敏感处理"):
        assert anchor in facts.BUSINESS_PROFILE_FACTS, anchor


def test_vpn_policy_and_sensitivity_facts_wired():
    """VPN政策接入域名扫描建议通道, 敏感分级接入 massops 内容定性(接线不回退)。"""
    import api
    import massops
    assert "VPN_POLICY_FACTS" in inspect.getsource(api)
    assert "SENSITIVITY_TIER_FACTS" in inspect.getsource(massops)
    import facts
    assert "不算风险" in facts.VPN_POLICY_FACTS
    assert "high=" in facts.SENSITIVITY_TIER_FACTS and "一律none" in facts.SENSITIVITY_TIER_FACTS
