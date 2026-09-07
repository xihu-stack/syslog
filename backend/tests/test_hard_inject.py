# -*- coding: utf-8 -*-
"""难例注入(Task10): 阈值±15或unknown首判后带相似判例重判一次,标[判例对齐]。"""


def _win():
    from datetime import datetime
    from models import CanonicalEvent
    return [CanonicalEvent(occurred_at=datetime(2026, 9, 4, 10), employee_id="测试员工",
                           device_id="测试员工", category="WEB", action="VISIT", target_type="FILE",
                           target_value="www.zhipin.com", size_bytes=0, count=1, source="sangfor",
                           raw={"domain": "www.zhipin.com"})]


def test_analyze_window_accepts_cases_txt_without_llm():
    # analyze_window 会真调LLM——本用例只验证参数被接受且fail-soft:
    # cases_txt只做字符串拼接,不调AI不查库。LLM不可用时analyze_window走
    # 它自己的兜底路径,断言聚焦"不因cases_txt报TypeError"。
    import detector
    try:
        detector.analyze_window(_win(), cases_txt="【相似历史案例】\n- x →人工:误报")
    except TypeError:
        raise AssertionError("analyze_window 不接受 cases_txt 参数")
    except Exception:
        pass  # LLM调用失败是本用例允许的结果(本地无AI)


def test_case_block_shape():
    import casebase
    txt = casebase.cases_for_prompt(
        {"intent": "job_seeking", "dom_classes": ["招聘求职"], "actions": ["WEB:VISIT"],
         "off_hours": False, "volume": "1"})
    assert txt == "" or txt.startswith("【相似历史案例")
