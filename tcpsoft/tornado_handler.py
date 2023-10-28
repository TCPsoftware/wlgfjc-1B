import tornado.web
import socketio
import time
import uuid
import os

from tcpsoft import user_manage
from tcpsoft import file_control
from tcpsoft import socketio_handler
from tcpsoft.configuration import SESSION_UUID_EXPIRATION_TIME
import secrets
import base64
import qrcode
import jinja2
import hashlib

# 设置模板目录
jinja_loader = jinja2.FileSystemLoader("template")
jinja_env = jinja2.Environment(loader=jinja_loader)


def create_tornado_app_sio():
    # 调用函数创建socketio实例
    sio = socketio_handler.create_sio()
    # 创建Tornado应用
    app = tornado.web.Application([
        (r"/socket.io/", socketio.get_tornado_handler(sio)),
        (r"/hello", HelloHandler),
        (r"/", WebRootHandler),
        (r"/register", RegisterHandler),
        (r"/login", LoginHandler),
        (r"/disk", DiskHandler),
        (r"/delete_file", DeleteFileHandler),
        (r"/(.*)", tornado.web.StaticFileHandler, {"path": "./static/", "default_filename": "index.html"}),
    ], cookie_secret=str(uuid.uuid4()))
    return app, sio


def login_required(handler_method):
    def check_login_wrapper(self, *args, **kwargs):
        session_uuid = self.get_cookie("u")
        state = user_manage.login_state_check(session_uuid)
        if not state:
            self.redirect("/?msg=未登录。")
        else:
            handler_method(self, *args, **kwargs)

    return check_login_wrapper


def get_session_uuid(req: tornado.web.RequestHandler):
    session_uuid = req.get_cookie("u")
    if type(session_uuid) == bytes:
        session_uuid = session_uuid.decode()
    if session_uuid and user_manage.login_state_check(session_uuid):
        return session_uuid
    else:
        return None


class HelloHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("hello, world.")


class WebRootHandler(tornado.web.RequestHandler):
    def get(self):
        session_uuid = get_session_uuid(self)
        template = jinja_env.get_template("index.html")
        html = template.render()
        self.write(html)


class RegisterHandler(tornado.web.RequestHandler):
    def get(self):
        template = jinja_env.get_template("register.html")
        html = template.render()
        self.write(html)

    def post(self):
        usr = self.get_body_argument("username", "__none__")
        usr = usr.lower()  # 将用户名转换为小写
        pwd = self.get_body_argument("password", "__none__")
        if usr == "__none__" or pwd == "__none__":  # 检查是否为空
            template = jinja_env.get_template("register.html")
            html = template.render(msg="用户名或密码为空")
            self.write(html)
        elif not user_manage.is_valid_username(usr):
            template = jinja_env.get_template("register.html")
            html = template.render(msg=f"用户名只能包含字母、数字和下划线")
            self.write(html)
        elif user_manage.check_username_exist(usr):  # 如果用户名已存在
            template = jinja_env.get_template("register.html")
            html = template.render(msg=f"该用户名【{usr}】已注册！")
            self.write(html)
        else:
            pwd_hash = hashlib.md5(pwd.encode()).hexdigest()
            user_manage.user_register(usr, pwd_hash)
            # self.write(f"Hello, {usr} (POST)")
            self.redirect("/?msg=注册成功，请登录。")  # 注册成功后重定向到首页
        dbg = 1


class LoginHandler(tornado.web.RequestHandler):
    def post(self):
        usr = self.get_body_argument("username", "__tcpsoft_none__")
        usr = usr.lower()  # 将用户名转换为小写
        pwd = self.get_body_argument("password", "__tcpsoft_none__")
        if usr == "__tcpsoft_none__" or pwd == "__tcpsoft_none__":
            self.redirect("/?msg=用户名和密码不能为空")
        elif not user_manage.is_valid_username(usr):
            self.redirect("/?msg=用户名只能包含字母、数字和下划线")
        else:
            pwd_hash = hashlib.md5(pwd.encode()).hexdigest()
            login_session_uuid = user_manage.user_login(usr, pwd_hash)
            if login_session_uuid is None:
                self.redirect("/?msg=登陆失败，用户不存在或用户名与密码不匹配")
            else:
                self.set_cookie("u", login_session_uuid,
                                       expires=time.time() + SESSION_UUID_EXPIRATION_TIME)
                self.redirect("/disk")
        dbg = 1


class DiskHandler(tornado.web.RequestHandler):
    @login_required
    def get(self):
        session_uuid = get_session_uuid(self)
        username = user_manage.get_username(session_uuid)
        user_files = file_control.list_user_files(username)
        template = jinja_env.get_template("disk.html")
        html = template.render(files=user_files)
        self.write(html)


class DeleteFileHandler(tornado.web.RequestHandler):
    @login_required
    def post(self):
        session_uuid = get_session_uuid(self)
        username = user_manage.get_username(session_uuid)
        filename = self.get_body_argument("filename", "__none__")
        delete_status = file_control.delete_user_file(username, filename)
        if delete_status:
            response_data = {"msg": "success"}
        else:
            response_data = {"msg": "error"}
        self.set_header("Content-Type", "application/json")
        self.write(response_data)

# # 生成随机的 128 位字节序列
# random_bytes = secrets.token_bytes(16)

# # 将随机字节序列进行 Base32 编码
# base32_key = base64.b32encode(random_bytes).decode()

# # 创建二维码
# qr = qrcode.QRCode(
#     version=1,
#     error_correction=qrcode.constants.ERROR_CORRECT_L,
#     box_size=10,
#     border=4,
# )
# qr.add_data(base32_key)
# qr.make(fit=True)

# # 创建二维码图片
# img = qr.make_image(fill_color="black", back_color="white")

# # 将图片保存到内存中
# img_bytes = io.BytesIO()
# img.save(img_bytes, format="PNG")

# class TwoFactorAuthHandler(tornado.web.RequestHandler):
#     def get(self):
#         # 发送生成的二维码图片到响应
#         self.set_header("Content-Type", "image/png")
#         self.write(img_bytes.getvalue())

