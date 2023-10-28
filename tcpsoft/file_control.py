import os
import shutil
from datetime import datetime

from tcpsoft.configuration import upload_dirname


def upload_file_exists(username, filename):
    if filename == "__none__":
        return True
    file_path = os.path.join(upload_dirname, username, filename)
    return os.path.exists(file_path)


def format_bytes(bytes_count):
    if bytes_count < 1024:
        return f"{bytes_count} B"
    elif bytes_count < 1024 * 1024:
        return f"{bytes_count / 1024:.2f} KB"
    elif bytes_count < 1024 * 1024 * 1024:
        return f"{bytes_count / (1024 * 1024):.2f} MB"
    else:
        return f"{bytes_count / (1024 * 1024 * 1024):.2f} GB"


def list_user_files(username):
    user_root = os.path.join(upload_dirname, username)
    if not os.path.exists(user_root):
        os.makedirs(user_root)
    file_list = []
    for filename in os.listdir(user_root):
        file_path = os.path.join(user_root, filename)
        if os.path.isfile(file_path):
            file_info = {
                "name": filename,
                "size": os.path.getsize(file_path),
                "size_humanreadable": format_bytes(os.path.getsize(file_path)),
                "created_time": datetime.fromtimestamp(os.path.getctime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
            }
            file_list.append(file_info)
    dbg = 1
    return file_list


def write_cache_file(username, filename, binary_data, start_offset, end_offset):
    file_path = os.path.join(upload_dirname, username+"_"+filename)
    with open(file_path, 'a+b') as file:
        # 将二进制数据写入文件的指定位置
        file.seek(start_offset)
        file.write(binary_data)


def move_cache_to_user_dir(username, filename):
    cache_file_path = os.path.join(upload_dirname, username+"_"+filename)
    user_file_path = os.path.join(upload_dirname, username, filename)
    # 移动文件
    shutil.move(cache_file_path, user_file_path)


def delete_user_file(username, filename):
    file_path = os.path.join(upload_dirname, username, filename)
    if filename == "__none__":
        return False
    elif os.path.exists(file_path):  # 检查文件是否存在
        try:
            os.remove(file_path)  # 删除文件
            return True
        except Exception as e:
            print(f"无法删除文件 {file_path}: {e}")
            return False
    else:
        return False


class User_File:
    def __init__(self, username, filename, start_offset, end_offset):
        self.filepath = os.path.join(upload_dirname, username, filename)
        self.start_byte_offset = start_offset
        self.end_byte_offset = end_offset-1

    def read_bytes(self, block_size=4096):
        with open(self.filepath, 'rb') as file:  # 开启一个文件对象，使用迭代器返回多片数据，而不是多次打开和定位文件
            file.seek(self.start_byte_offset)  # 定位到start
            while file.tell() <= self.end_byte_offset:
                start_byte_seq = file.tell()
                data = file.read(min(block_size, self.end_byte_offset + 1 - file.tell()))
                end_byte_seq = file.tell()
                if not data:
                    break
                yield data, start_byte_seq, end_byte_seq
