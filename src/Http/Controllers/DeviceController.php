<?php

namespace Yljphp\GoogleAuthenticator\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Yljphp\GoogleAuthenticator\Services\DeviceService;

class DeviceController extends Controller
{
    /**
     * @var DeviceService
     */
    protected $devices;

    public function __construct(DeviceService $devices)
    {
        $this->devices = $devices;
    }

    /**
     * 心跳探针
     *
     * 设备已被顶号时，请求会被 AdminDeviceCheckMiddleware 拦下并返回 401 + valid:false，
     * 因此走到这里一定是有效设备。
     */
    public function status(Request $request)
    {
        return response()->json([
            'code'  => 0,
            'valid' => true,
            'msg'   => '',
        ]);
    }

    /**
     * 心跳脚本
     */
    public function heartbeat()
    {
        return response()->view('google-authenticator::device-heartbeat', [
            'statusUrl' => admin_base_path('device/status'),
            'loginUrl'  => admin_base_path('auth/login'),
            'interval'  => (int)config('google-authenticator.single_login.heartbeat_interval', 30),
        ], 200, [
            'Content-Type' => 'application/javascript',
            'Cache-Control' => 'private, max-age=60',
        ]);
    }
}
