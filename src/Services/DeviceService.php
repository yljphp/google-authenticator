<?php

namespace Yljphp\GoogleAuthenticator\Services;

use Encore\Admin\Facades\Admin;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

/**
 * 单设备登录：设备令牌签发与校验
 *
 * 令牌同时保存在服务端（cache，本项目为 redis）和客户端：
 *   - session：主来源，随登录会话存在
 *   - cookie：兜底来源，session 过期后靠 remember cookie 恢复会话时仍能比对
 *
 * 服务端只保留"当前有效令牌"，新设备登录即覆盖，旧设备下次请求即被判定下线。
 */
class DeviceService
{
    /**
     * session 中的令牌键名
     */
    const SESSION_KEY = 'admin_device_token';

    public function enabled(): bool
    {
        return (bool)config('google-authenticator.single_login.enabled', false);
    }

    /**
     * 登录成功后签发新令牌并绑定到当前设备
     *
     * 开关关闭时原样返回，不写 session、不写 Redis
     *
     * @param mixed $user
     */
    public function bind(Request $request, $user, bool $remember, $response)
    {
        if (!$this->enabled()) {
            return $response;
        }

        $token = Str::random(40);

        $request->session()->put(self::SESSION_KEY, $token);
        $this->storeToken($user->getAuthIdentifier(), $token);

        return $response->withCookie($this->makeCookie($token, $remember));
    }

    /**
     * 校验当前请求所属设备是否仍是有效设备
     */
    public function check(Request $request, $userId): array
    {
        $token = $this->clientToken($request);

        if (empty($token)) {
            return $this->result(false, 'no_token');
        }

        $server = $this->serverToken($userId);

        if (empty($server)) {
            // 服务端没有有效令牌（Redis 重启 / 令牌过期），认领当前设备
            $this->storeToken($userId, $token);

            return $this->result(true, 'claimed');
        }

        if (!hash_equals($server, $token)) {
            return $this->result(false, 'kicked');
        }

        return $this->result(true, 'ok');
    }

    /**
     * 强制当前设备下线
     */
    public function kick(Request $request, $userId, string $reason): void
    {
        Log::warning('admin_device_kicked', [
            'uid'    => (int)$userId,
            'reason' => $reason,
            'ip'     => $request->ip(),
            'agent'  => $request->userAgent(),
        ]);

        Admin::guard()->logout();

        $request->session()->invalidate();
    }

    /**
     * 客户端持有的令牌：session 优先，cookie 兜底
     */
    public function clientToken(Request $request): ?string
    {
        $token = $request->session()->get(self::SESSION_KEY);

        if (!empty($token)) {
            return (string)$token;
        }

        $cookie = $request->cookie($this->cookieName());

        return empty($cookie) ? null : (string)$cookie;
    }

    public function serverToken($userId): ?string
    {
        $token = Cache::get($this->serverKey($userId));

        return empty($token) ? null : (string)$token;
    }

    public function kickedMessage(): string
    {
        return (string)config(
            'google-authenticator.single_login.kicked_message',
            '您的账号已在其他设备登录，当前设备已被强制下线，请重新登录。'
        );
    }

    public function cookieName(): string
    {
        return (string)config('google-authenticator.single_login.cookie_name', 'admin_device_token');
    }

    protected function storeToken($userId, string $token): void
    {
        Cache::put(
            $this->serverKey($userId),
            $token,
            (int)config('google-authenticator.single_login.token_ttl', 31536000)
        );
    }

    protected function serverKey($userId): string
    {
        return config('google-authenticator.single_login.cache_prefix', 'admin:device:') . $userId;
    }

    protected function result(bool $valid, string $reason): array
    {
        return [
            'valid'  => $valid,
            'reason' => $reason,
            'msg'    => $valid ? '' : $this->kickedMessage(),
        ];
    }

    /**
     * 设备令牌 cookie
     *
     * 由 EncryptCookies 中间件统一加密，httpOnly 禁止 JS 读取；
     * 勾选"记住我"才落长期 cookie，否则用浏览器会话 cookie，与登录态生命周期一致
     */
    protected function makeCookie(string $token, bool $remember = false)
    {
        $minutes = $remember
            ? (int)config('google-authenticator.single_login.cookie_lifetime', 525600)
            : 0;

        return Cookie::make(
            $this->cookieName(),
            $token,
            $minutes,
            admin_base_path(''),
            null,
            !app()->environment('local'),
            true,
            false,
            'lax'
        );
    }
}
