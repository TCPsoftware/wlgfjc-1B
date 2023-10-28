function human_readable_size(bytesCount) {
    if (bytesCount < 1024) {
        return bytesCount + " B";
    } else if (bytesCount < 1024 * 1024) {
        return (bytesCount / 1024).toFixed(2) + " KB";
    } else if (bytesCount < 1024 * 1024 * 1024) {
        return (bytesCount / (1024 * 1024)).toFixed(2) + " MB";
    } else {
        return (bytesCount / (1024 * 1024 * 1024)).toFixed(2) + " GB";
    }
}

function create_socketio_thread(start_offset, end_offset, download_when_done = true, done_callback = null, auto_reconnect = false) {
    let userID = document.cookie.replace(
        /(?:(?:^|.*;\s*)u\s*\=\s*([^;]*).*$)|^.*$/, "$1",
    );
    let socket = io.connect("wss://wlgfjc-test.tcpsoft.app", {
        transports: ["websocket"],
        pingInterval: 60000,
        pingTimeout: 25000,
        auth: {
            "userID": userID
        }
    });
    socket.download_when_done = download_when_done;
    socket.tcpsoft_cache = {};
    socket.tcpsoft_cache.file_cache = [];
    socket.tcpsoft_cache.byte_start = start_offset;
    socket.tcpsoft_cache.byte_end = start_offset;
    socket.tcpsoft_cache.byte_finish = end_offset;
    socket.tcpsoft_cache.finished = false;
    socket.tcpsoft_upload = {};
    socket.tcpsoft_upload.byte_start = 0;
    socket.tcpsoft_upload.byte_end = 0;
    socket.tcpsoft_upload.byte_finish = 0;
    socket.tcpsoft_upload.finished = false;

    socket.on("connect", function () {
        console.log("Socket.IO connected for user: " + socket.id);
    });

    socket.on("response", function (data) {
        var messagesDiv = document.getElementById("messages");
        messagesDiv.innerHTML += "<p>Received: " + data + "</p>";
        console.log("Received response for user " + socket.id + ": ", data);
    });

    socket.on("disconnect", function () {
        console.log("Socket.IO disconnected for user: ", socket.id, socket);
        // debugger
        if(auto_reconnect){
            setTimeout(()=>{socket.connect();}, 2000);
        } else {
            let dbg=1;
        }
    });

    socket.on('file_download', function (file_info, binaryData) {
        file_info_demo_response = {
            "filename": "hello-uniapp-master.zip", "total_start": 0,"total_end": 833627,
            "slice_start": 0,"slice_end": 4096,"slice_length": 4096, "remain_bytes": 829531
        }
        // console.log('Received text data:', file_info);
        // console.log('Received binary data:', binaryData);

        if (file_info["slice_length"] > 0) { // 有数据才加入缓存
            if (file_info["slice_start"] === socket.tcpsoft_cache.byte_end) {
                socket.tcpsoft_cache.file_cache.push(binaryData);
                socket.tcpsoft_cache.byte_end = file_info["slice_end"];
            } else {
                // 如果不连续，输出提示
                console.log('sequence wrong:', socket, file_info);
                socket.disconnect();
                return false;
            }
        }
    
        if (file_info["remain_bytes"] === 0) {
            // 单线程下载191M的视频：
            // 200370613/48/1024/1024=3.981006403764089 MB/s
            // 单线程下载1.28G的视频
            // 1378078305/48/1024/1024=27.37995594739914 MB/s

            console.warn("File download finish. download_when_done=",socket.download_when_done);
            socket.tcpsoft_cache.finished = true;
            if(socket.download_when_done){
                console.warn("Merging and downloading files...");
                $("#messages").append(`<p>正在将文件【${file_info["filename"]}】保存到本地。</p>`);
                let blob = new Blob(socket.tcpsoft_cache.file_cache);
                let url = URL.createObjectURL(blob);
                let a = document.createElement('a');
                a.href = url;
                a.download = file_info["filename"];
                a.click();
                URL.revokeObjectURL(url);
                // 清空缓存
                // socket.tcpsoft_cache = {};
                socket.tcpsoft_cache.file_cache = [];
                // socket.tcpsoft_cache.byte_start = 0;
                // socket.tcpsoft_cache.byte_end = 0;
                // socket.tcpsoft_cache.byte_finish = 0;
                // socket.tcpsoft_cache.finished = false;
            } else {
                if(typeof(done_callback) == "function"){
                    done_callback();
                }
            }
        }
    });

    return socket;
}

