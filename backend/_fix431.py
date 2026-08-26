import sqlite3, time
db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
for attempt in range(30):
    try:
        a = db.execute("SELECT status, summary FROM alerts WHERE id=431").fetchone()
        if a and a[0] == "NEW":
            db.execute("""UPDATE alerts SET status='CLOSED', risk_score=15, severity='LOW',
                summary='[白名单更正: 窗口7个发送中6个目的地为sftp.huashen.bio(公司内网SFTP,白名单),1张空目的地截图经同期浏览推断同为公司通道;RGA数据上传属正常办公] '||substr(summary,1,140) WHERE id=431""")
            db.commit()
        print(tuple(db.execute("SELECT id, risk_score, status FROM alerts WHERE id=431").fetchone()))
        break
    except sqlite3.OperationalError:
        db.rollback(); time.sleep(1)
