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


def test_prompt_disguise_four_questions():
    """外发深度分析四问(2026-09-07): ④伪装检查——RENAME/压缩包/批量打开不符文件。"""
    import detector
    sp = detector.SYSTEM_PROMPT
    assert "外发深度分析——四问" in sp
    assert "疑似伪装外发" in sp
    assert "压缩包外发的file_sensitivity至少mid" in sp
    assert "文件名与工作内容错位" in sp  # ②问画像匹配


def test_prompt_moonlight_marker():
    """在职牟利留痕(2026-09-07): 私活/飞单→baseline_deviation+'疑似在职牟利:'。"""
    import detector
    sp = detector.SYSTEM_PROMPT
    assert "疑似在职牟利" in sp
    assert "在职利益冲突留痕" in sp
