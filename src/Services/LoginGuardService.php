<?php

namespace Yljphp\GoogleAuthenticator\Services;

use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * 后台登录限流与失败锁定
 *
 * 三个维度同时计数，任一维度超阈值即写封禁标记：
 * - 账号+IP：抓单点暴力破解（默认 5 次）
 * - 账号：抓换 IP 分布式喷洒 2FA 验证码（默认 20 次）
 * - IP：抓单点批量撞库（默认 30 次）
 *
 * 计数走 RateLimiter（底层为 cache 驱动，本项目为 redis），
 * 封禁标记走独立 cache key，便于单独解除。
 */
class LoginGuardService
{
    /**
     * @var RateLimiter
     */
    protected $limiter;

    public function __construct(RateLimiter $limiter)
    {
        $this->limiter = $limiter;
    }

    public function enabled(): bool
    {
        return (bool)config('google-authenticator.login_guard.enabled', true);
    }

    /**
     * 账号或 IP 是否处于锁定期
     */
    public function isLocked(string $username, string $ip): bool
    {
        if (!$this->enabled()) {
            return false;
        }

        return Cache::has($this->accountBanKey($username, $ip))
            || Cache::has($this->accountOnlyBanKey($username))
            || Cache::has($this->ipBanKey($ip));
    }

    /**
     * 记录一次登录失败并按阈值触发锁定
     */
    public function recordFailure(string $username, string $ip, Request $request, string $reason): void
    {
        if (!$this->enabled()) {
            return;
        }

        $this->hit(
            $this->accountLimiterKey($username, $ip),
            (int)config('google-authenticator.login_guard.account_attempts', 5),
            (int)config('google-authenticator.login_guard.account_decay', 900),
            $this->accountBanKey($username, $ip),
            (int)config('google-authenticator.login_guard.account_ban', 900)
        );

        $this->hit(
            $this->accountOnlyLimiterKey($username),
            (int)config('google-authenticator.login_guard.account_total_attempts', 20),
            (int)config('google-authenticator.login_guard.account_decay', 900),
            $this->accountOnlyBanKey($username),
            (int)config('google-authenticator.login_guard.account_ban', 900)
        );

        $this->hit(
            $this->ipLimiterKey($ip),
            (int)config('google-authenticator.login_guard.ip_attempts', 30),
            (int)config('google-authenticator.login_guard.ip_decay', 900),
            $this->ipBanKey($ip),
            (int)config('google-authenticator.login_guard.ip_ban', 3600)
        );

        Log::warning('admin_login_failed', [
            'uid'     => 0,
            'account' => $username,
            'reason'  => $reason,
            'ip'      => $ip,
            'agent'   => $request->userAgent(),
        ]);
    }

    /**
     * 记录登录成功并清空计数
     */
    public function recordSuccess(string $username, string $ip, Request $request, int $userId = 0): void
    {
        if ($this->enabled()) {
            $this->clear($this->accountLimiterKey($username, $ip));
            $this->clear($this->accountBanKey($username, $ip));
            $this->clear($this->accountOnlyLimiterKey($username));
            $this->clear($this->accountOnlyBanKey($username));
            $this->clear($this->ipLimiterKey($ip));
        }

        Log::info('admin_login_success', [
            'uid'     => $userId,
            'account' => $username,
            'ip'      => $ip,
            'agent'   => $request->userAgent(),
        ]);
    }

    public function failedMessage(): string
    {
        return (string)config('google-authenticator.login_guard.failed_message', '用户名、密码或验证码错误');
    }

    public function lockedMessage(): string
    {
        return (string)config('google-authenticator.login_guard.locked_message', '登录失败次数过多，该账号已被临时锁定，请稍后再试');
    }

    /**
     * 计数 + 超阈值写入封禁标记
     *
     * 先累加再比较，保证「第 N 次失败即锁」，不多放行一次
     */
    protected function hit(string $limiterKey, int $maxAttempts, int $decay, string $banKey, int $banSeconds): void
    {
        $attempts = $this->limiter->hit($limiterKey, $decay);

        if ($attempts >= $maxAttempts && !Cache::has($banKey)) {
            Cache::put($banKey, 1, $banSeconds);
        }
    }

    /**
     * 清空计数与封禁标记
     */
    protected function clear(string $key): void
    {
        $this->limiter->clear($key);
        Cache::forget($key);
    }

    protected function accountLimiterKey(string $username, string $ip): string
    {
        return 'admin:login:fail:account:' . md5($username . '|' . $ip);
    }

    protected function accountBanKey(string $username, string $ip): string
    {
        return 'admin:login:ban:account:' . md5($username . '|' . $ip);
    }

    protected function accountOnlyLimiterKey(string $username): string
    {
        return 'admin:login:fail:acct:' . md5($username);
    }

    protected function accountOnlyBanKey(string $username): string
    {
        return 'admin:login:ban:acct:' . md5($username);
    }

    protected function ipLimiterKey(string $ip): string
    {
        return 'admin:login:fail:ip:' . md5($ip);
    }

    protected function ipBanKey(string $ip): string
    {
        return 'admin:login:ban:ip:' . md5($ip);
    }
}
