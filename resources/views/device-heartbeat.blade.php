(function () {
    if (window.__adminDeviceHeartbeat) {
        return;
    }
    window.__adminDeviceHeartbeat = true;

    var statusUrl = {!! json_encode($statusUrl, JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_TAG | JSON_HEX_AMP) !!};
    var loginUrl = {!! json_encode($loginUrl, JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_TAG | JSON_HEX_AMP) !!};
    var interval = {!! (int) $interval * 1000 !!};
    var defaultMsg = '您的账号已在其他设备登录，当前设备已被强制下线，请重新登录。';
    var stopped = false;

    function stop() {
        stopped = true;
    }

    // 提示后跳转：toastr 有 2 秒展示时间，alert 则是阻塞式确认
    function notify(msg) {
        if (window.toastr && typeof window.toastr.error === 'function') {
            window.toastr.error(msg);
            window.setTimeout(function () {
                window.location.href = loginUrl;
            }, 2000);
            return;
        }

        window.alert(msg);
        window.location.href = loginUrl;
    }

    function check() {
        if (stopped) {
            return;
        }

        var xhr = new XMLHttpRequest();
        xhr.open('GET', statusUrl, true);
        xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        // 显式声明 JSON：否则 expectsJson() 判false，顶号时会拿到登录页 HTML 而不是 401 JSON
        xhr.setRequestHeader('Accept', 'application/json');

        xhr.onreadystatechange = function () {
            if (xhr.readyState !== 4 || stopped) {
                return;
            }

            // 顶号时服务端返回 401 + valid:false；会话彻底失效时返回登录页，二者都要处理
            if (xhr.status !== 200 && xhr.status !== 401) {
                return;
            }

            var data = null;
            try {
                data = JSON.parse(xhr.responseText);
            } catch (e) {
                return;
            }

            if (!data || data.valid !== false) {
                return;
            }

            stop();
            notify(data.msg || defaultMsg);
        };

        xhr.send();
    }

    window.setInterval(check, interval);
})();
