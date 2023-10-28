import sqlite3


def init_db():
    # 指定 SQLite 数据库文件名
    db_file = "user.db"

    # 创建或连接到数据库
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    # 创建用户表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user (
            uid INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            pwd_hash TEXT NOT NULL,
            otp_seed TEXT NOT NULL
        )
    ''')

    # 提交更改并关闭数据库连接
    conn.commit()
    conn.close()
