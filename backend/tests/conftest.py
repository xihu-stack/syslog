# -*- coding: utf-8 -*-
"""本地单测基建: DATABASE_URL 指到临时sqlite(绝不用backend/data/ipguard.db),
并把backend加进sys.path。必须在import db/api之前生效——conftest收集期先跑。"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_TMPDB = os.path.join(tempfile.gettempdir(), "soul_test.db").replace("\\", "/")
os.environ["DATABASE_URL"] = "sqlite:///" + _TMPDB

import db  # noqa: E402
db.init_db()


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_tables():
    """每测清空判例/处置相关表,测试互不污染。"""
    from db import Session, FeedbackRow, ExceptionRow
    s = Session()
    try:
        for _m in (FeedbackRow, ExceptionRow):
            for _r in s.query(_m).all():
                s.delete(_r)
        s.commit()
    finally:
        s.close()
    yield
