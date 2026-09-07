# -*- coding: utf-8 -*-
def test_prompt_chars_counts_content():
    import llm_client
    msgs = [{"role": "system", "content": "abc"}, {"role": "user", "content": "你好"}]
    assert llm_client.prompt_chars(msgs) == 5  # 3 + 2(中文按字符计)


def test_prompt_chars_empty_safe():
    import llm_client
    assert llm_client.prompt_chars([]) == 0
    assert llm_client.prompt_chars(None) == 0
    assert llm_client.prompt_chars([{"role": "user"}]) == 0


def test_stats_has_chars():
    import llm_client
    assert "chars" in llm_client.stats()


def test_system_prompt_contains_output_instruction():
    import detector
    sp = detector._system_prompt()
    assert sp.startswith("你是企业员工终端行为分析助手")
    # user尾部恒定指令已并入system(常量区归位)
    assert "今日累计" in sp and "请输出 JSON" in sp


def test_system_prompt_stable():
    import detector
    assert detector._system_prompt() == detector._system_prompt()
