import sqlite3

# 指定 SQLite 数据库文件名
db_file = "user.db"

# 创建或连接到数据库
conn = sqlite3.connect(db_file)
cursor = conn.cursor()

# 插入一条用户数据
cursor.execute("INSERT INTO user (username, pwd_hash, otp_seed) VALUES (?, ?, ?)", ("john_doe", "hashed_password", "otp_seed_value"))

# 提交更改并关闭数据库连接
conn.commit()
conn.close()