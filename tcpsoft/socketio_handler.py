import socketio
from tcpsoft.configuration import socketio_ping_interval, socketio_ping_timeout
from tcpsoft import user_manage
from tcpsoft import file_control


upload_auth_tokens = {} # 用户上传文件时的临时授权token

def create_sio():
    # 创建Socket.IO实例
    sio = socketio.AsyncServer(async_mode='tornado',
                            cors_allowed_origins="*",
                            ping_interval=socketio_ping_interval, # 每60秒发送一次ping
                            ping_timeout=socketio_ping_timeout)  # 如果25秒内没有收到pong，则视为超时)

    @sio.on("connect")
    async def handle_connect(sid, environ, auth):
        userID = auth["userID"]
        if user_manage.login_state_check(userID):
            user_manage.socketio_map_add(sid, userID)
            print(f'Connection established for SID: {sid}')
        else:
            pass
            print(f'Connection cutdown for SID: {sid}')
            await sio.disconnect(sid)
        dbg=1
        

    @sio.on("disconnect")
    async def handle_disconnect(sid):
        lookup_result = user_manage.socketio_map_remove(sid)
        if lookup_result:
            userID, username = lookup_result
            for key, value in upload_auth_tokens.copy().items():
                if value[0] == userID:
                    del upload_auth_tokens[key]
        print('disconnect ', sid)

    @sio.on('message')
    async def handle_message(sid, data):
        # 处理从客户端接收的消息
        userID, username = user_manage.socketio_get_info(sid)
        print('message event get an message {} from {}'.format(data, sid))
        await sio.emit('response', f'Server received user【{username}】: 【{str(data)}】', room=sid)

    @sio.on("file_download")
    async def handle_file_download(sid, json_info):
        userID, username = user_manage.socketio_get_info(sid)
        filename = json_info['filename']
        start_offset = int(json_info['start_offset'])
        end_offset = int(json_info['end_offset'])
        block_size = int(json_info.get('block_size', 4096))
        file_size_all = end_offset - start_offset
        user_file = file_control.User_File(username, filename, start_offset, end_offset)
        # ii = []
        for binary_data_slice, start_seq, end_seq in user_file.read_bytes(block_size):
            # ii.append(i)
            await sio.emit('file_download', ({
                "filename": filename,
                "total_start": start_offset,
                "total_end": end_offset,
                "slice_start": start_seq,
                "slice_end": end_seq,
                "slice_length": end_seq - start_seq,
                "remain_bytes": end_offset - end_seq
            }, binary_data_slice), room=sid)
        # binary_data = b'\x48\x65\x6C\x6C\x6F'*8000  # 二进制数据，例如 "Hello"
        # await sio.emit('file_download', (json_info, binary_data), room=sid)
        # await sio.emit('file_download', (json_info, binary_data), room=sid)
        dbg=1

    @sio.on("file_upload_request")
    async def handle_file_upload_request(sid, file_info):
        userID, username = user_manage.socketio_get_info(sid)
        filename = "__none__"
        if "filename" in file_info.keys():
            filename = file_info["filename"]
        else:
            # await sio.emit('file_upload_request', {"ok":False, "msg":"error: no filename specified"}, room=sid)
            return {"ok":False, "msg":"error: no filename specified"}
        if file_control.upload_file_exists(username, filename):
            # await sio.emit('file_upload_request', {"ok":False, "msg":"error: 文件已存在"}, room=sid)
            return {"ok":False, "msg":"error: 文件已存在"}
        upload_token = user_manage.generate_session_id()
        upload_auth_tokens[upload_token] = [userID, username, filename]
        # await sio.emit("file_upload_request", {"ok":True, "token":upload_token, "msg":"success"}, room=sid)
        print("发放文件上传token: ", upload_token, [userID, username, filename])
        return {"ok":True, "token":upload_token, "msg":"success, filename: " + filename}

    @sio.on("file_upload")
    async def handle_file_upload(sid, file_info, binary_data):
        auth_token = file_info["auth_token"]
        if auth_token in upload_auth_tokens: # 认证令牌有效
            userID, username, filename = upload_auth_tokens[auth_token]
            start_offset = file_info["start_offset"]
            end_offset = file_info["end_offset"]
            file_control.write_cache_file(username, filename, binary_data, start_offset, end_offset)
            if file_info["remain"] == 0: # 文件上传完成，保存文件并从缓存中删除
                file_control.move_cache_to_user_dir(username, filename)
                del upload_auth_tokens[auth_token]
            return {"confirm_start_offset": start_offset, "confirm_end_offset": end_offset}
        else: # 无效的认证令牌，拒绝上传，断开连接
            await sio.disconnect(sid)


    return sio

# # 多线程文件操作的字节分配
# bytes_all = 114514
# workers = 8
# block_size = 4096
# worker_block_size = workers * block_size
# num_blocks = bytes_all // worker_block_size

# for w in range(1, workers + 1):
#     start = (w - 1) * num_blocks * block_size
#     end = w * num_blocks * block_size
#     print(f"worker {w}: [{(w - 1)}*{num_blocks}*{block_size}={start}, {w}*{num_blocks}*{block_size}={end})")

# remain_size = bytes_all % worker_block_size
# start_remain = workers * num_blocks * block_size
# end_remain = bytes_all + 1
# print(f"remain size: {remain_size} bytes")
# print(f"remain range: [{start_remain}, {end_remain}), {end_remain-start_remain}")


