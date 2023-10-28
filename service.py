import os

import tornado.ioloop

from tcpsoft.configuration import upload_dirname
from tcpsoft.init_db import init_db
from tcpsoft.tornado_handler import create_tornado_app_sio

if __name__ == "__main__":
    # check_domain_ip()
    init_db()  # 如果没有数据库，初始化数据库
    app, sio = create_tornado_app_sio()

    # 配置 HTTPS 服务器
    http_server = tornado.httpserver.HTTPServer(app, ssl_options={
        "certfile": "./certificate/fullchain1.pem",  # SSL 证书文件
        "keyfile": "./certificate/privkey1.pem",  # SSL 私钥文件
    })

    if not os.path.exists(upload_dirname):
        os.makedirs(upload_dirname)

    # 启动 Tornado 服务器
    http_server.listen(443)  # HTTPS 服务运行在 443 端口
    print(f"为保证本服务的连接使用，请手动修改本机hosts，添加一行为：（前面ip是服务器的ip）")
    print("127.0.0.1 wlgfjc-test.tcpsoft.app")
    print("网络服务正在启动。请在浏览器打开 https://wlgfjc-test.tcpsoft.app/ 来使用服务。")

    # 启动 Tornado I/O 循环
    tornado.ioloop.IOLoop.current().start()
    # 此行后面的代码不可执行



