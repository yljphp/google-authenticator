<?php

namespace Yljphp\GoogleAuthenticator\Http\Middleware;

use Closure;
use Encore\Admin\Facades\Admin;
use Yljphp\GoogleAuthenticator\Services\DeviceService;

/**
 * 单设备登录校验
 *
 * 挂在 laravel-admin 的 admin 中间件组末尾，因此 admin.auth 已经完成鉴权，
 * 到这里时 guard 内一定有登录用户。
 */
class AdminDeviceCheckMiddleware
{
    /**
     * @var DeviceService
     */
    protected $devices;

    public function __construct(DeviceService $devices)
    {
        $this->devices = $devices;
    }

    public function handle($request, Closure $next)
    {
        if (!$this->devices->enabled()) {
            return $next($request);
        }

        if (!Admin::guard()->check()) {
            return $next($request);
        }

        $user = Admin::guard()->user();
        $userId = $user->getAuthIdentifier();

        $result = $this->devices->check($request, $userId);

        if ($result['valid']) {
            return $next($request);
        }

        $this->devices->kick($request, $userId, $result['reason']);

        // 顶号提示同时走 flash 和错误袋：
        // flash 供自定义登录页展示，错误袋保证 laravel-admin 默认登录页也能显示
        $request->session()->flash('admin_device_notice', $result['msg']);

        if ($request->expectsJson()) {
            return response()->json([
                'code'  => 0,
                'valid' => false,
                'msg'   => $result['msg'],
            ], 401);
        }

        return redirect(admin_base_path('auth/login'))
            ->with('admin_device_notice', $result['msg'])
            ->withErrors(['username' => $result['msg']]);
    }
}
