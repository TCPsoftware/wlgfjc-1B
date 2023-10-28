import re
import uuid
import time
import sqlite3
import atexit
from .configuration import SESSION_UUID_EXPIRATION_TIME

# 指定 SQLite 数据库文件名
db_file = "user.db"
# 在应用初始化过程中创建数据库连接和游标
conn = sqlite3.connect(db_file)
cursor = conn.cursor()

login_user_uuid = {}

socketio_session_map = {}


def cleanup_expired_session_uuids():
    global login_user_uuid
    current_time = time.time()
    expired_sessions = [session_uuid for session_uuid, session_info in login_user_uuid.items() if
                        current_time - session_info[1] >= SESSION_UUID_EXPIRATION_TIME]
    for expired_uuid in expired_sessions:
        del login_user_uuid[expired_uuid]


def generate_session_id():
    return str(uuid.uuid4())


def login_state_check(session_uuid):
    global login_user_uuid
    if type(session_uuid) == bytes:
        session_uuid = session_uuid.decode()
    if session_uuid in login_user_uuid.keys():
        login_user_uuid[session_uuid][1] = time.time()
        return True
    else:
        return False


def login_state_add(session_uuid, username):
    global login_user_uuid
    login_user_uuid[session_uuid] = [username, time.time()]


def get_username(session_uuid):
    if session_uuid in login_user_uuid.keys():
        return login_user_uuid[session_uuid][0]
    else:
        return None


def check_username_exist(username):
    cursor.execute("SELECT * FROM user WHERE username=?", (username,))
    result = cursor.fetchone()  # 如果结果不为空，用户名已存在
    return result is not None


def is_valid_username(username):
    # 使用正则表达式验证用户名格式
    pattern = r"^[a-zA-Z0-9_]+$"
    return re.match(pattern, username) is not None


def user_register(username, pwd_hash, otp_seed="none"):
    cursor.execute("INSERT INTO user (username, pwd_hash, otp_seed) VALUES (?, ?, ?)",
                   (username, pwd_hash, otp_seed))
    conn.commit()


def close_connection():
    conn.close()


# 注册关闭数据库的操作，在应用退出时自动调用
atexit.register(close_connection)


def user_login(usr, pwd_hash):
    cursor.execute("SELECT * FROM user WHERE username=? AND pwd_hash=?", (usr, pwd_hash))
    result = cursor.fetchone()  # 尝试获取一行匹配的结果
    if result is not None:  # 登录成功
        session_uuid = generate_session_id()
        login_state_add(session_uuid, usr)
        return session_uuid
    else:
        return None


def socketio_map_add(sid, userID):
    global socketio_session_map, login_user_uuid
    username = get_username(userID)
    socketio_session_map[sid] = [userID,username]
    dbg=1


def socketio_map_remove(sid):
    global socketio_session_map
    if sid in socketio_session_map.keys():
        uid,uname = socketio_session_map[sid]
        del socketio_session_map[sid]
        return uid,uname
    else:
        return None

def socketio_get_info(sid):
    userID, username = socketio_session_map[sid]
    return userID, username