const url_string = window.location.href;
const url = new URL(url_string);
const msg = url.searchParams.get("msg");

$(function () {
    if (msg && msg.trim() !== "") {
        alert(msg);
    }
})

