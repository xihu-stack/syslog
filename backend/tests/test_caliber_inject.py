# -*- coding: utf-8 -*-
"""口径统一注入(Task9): 三AI通道共享【人工口径】段(italent事故架构修复)。
注: SYSTEM_PROMPT实际开头含"终端"二字——计划里的字面量笔误已修正(与
test_prompt_structure.py一致)。"""


def _seed():
    import casebase
    import dicts
    dicts.set_dict("risk_whitelist_domains", ["italent.cn"])
    casebase.record_case("disposition_fp", "测试员工", outcome="false_positive",
                         attribution="域名定性错",
                         fk={"intent": "job_seeking", "dom_classes": ["招聘求职"],
                             "actions": ["WEB:VISIT"], "off_hours": False, "volume": "1"},
                         ai_verdict="job_seeking/60: 测试AI结论")
    casebase._CALIBER_CACHE.update(txt="", ts=0.0)


def test_system_prompt_carries_caliber():
    _seed()
    import detector
    sp = detector._system_prompt()
    assert sp.startswith("你是企业员工终端行为分析助手")
    assert "人工口径" in sp and "italent.cn" in sp


def test_system_prompt_failsoft_without_cases():
    import detector
    sp = detector._system_prompt()
    assert sp.startswith("你是企业员工终端行为分析助手")  # 案例读失败/为空也不崩


def test_daygate_and_domain_scan_prompts_importable():
    # 冒烟: 两模块可导入且消息构造处引用caliber_text(编译期验证靠py_compile,
    # 运行期在容器密闭测试验证)
    import daygate
    import domain_scan
    import casebase
    assert callable(casebase.caliber_text)
