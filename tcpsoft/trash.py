import socket

def check_domain_ip():
    # 获取域名的IP地址
    host_name = "wlgfjc-test.tcpsoft.app"
    try:
        ip_address = socket.gethostbyname(host_name)
        if ip_address == "127.0.0.1": # 如果IP地址为127.0.0.1，则提供服务
            print("网络服务正在启动。请在浏览器打开 https://wlgfjc-test.tcpsoft.app/ 来使用服务。")
        else: # 不是127.0.0.1，则提示用户修改hosts
            print(f"wlgfjc-test.tcpsoft.app 的解析 ip 为【{ip_address}】，不是【127.0.0.1】，请手动修改本机hosts，修改为：")
            print("127.0.0.1 wlgfjc-test.tcpsoft.app")
            exit(2)
    except socket.gaierror: # 没有域名解析，则提示用户修改hosts
        print(f"无法解析域名 {host_name} 的 IP 地址。请手动修改本机hosts，添加：")
        print("127.0.0.1 wlgfjc-test.tcpsoft.app")
        exit(2)
    pass