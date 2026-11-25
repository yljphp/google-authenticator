Google 两步登陆验证
======
### laravel-admin 后台验证插件


1. 相对于验证码，安全很多；几乎是不会存在破解的方法
1. 验证码有时候无法识别，不方便操作
1. 一机一码，不会存在账号盗用的问题
1. 动态验证，每30秒生产一个验证码，安全更加保障

> composer require yljphp/google-authenticator

> php artisan migrate
```php
'google-authenticator'=> [
    'enable' => true,
    'authenticatorname' => '' //名称
],
```


```php
namespace App\Admin\Controllers;

use Yljphp\GoogleAuthenticator\Http\Controllers\AuthController as BaseAuthController;

```

### 登录限流与失败锁定（默认开启）

登录失败按三个维度计数，任一维度超阈值即锁定：

| 维度 | 默认阈值 | 默认锁定时长 |
|------|---------|-------------|
| 账号 + IP | 5 次 | 15 分钟 |
| 账号（跨 IP） | 20 次 | 15 分钟 |
| IP | 30 次 | 1 小时 |

用户名不存在、密码错误、验证码错误返回同一句提示，避免被当成"验证码 oracle"反复试。
登录成功后自动清空该账号/IP 的计数。

关闭：`.env` 里 `ADMIN_LOGIN_GUARD=false`

### 单设备登录（默认关闭）

同一后台账号只允许一个活跃设备。新设备登录后，旧设备在下一次请求时被强制下线，
并由心跳轮询（默认 30 秒）主动弹窗提示后跳回登录页。

开启：`.env` 里 `ADMIN_SINGLE_LOGIN=true`

设备令牌存在 Redis（key 前缀 `admin:device:`），同时写入 session 与 cookie
（cookie 由 EncryptCookies 加密、httpOnly，路径限定在后台前缀）。

心跳脚本地址为 `{后台前缀}/device/heartbeat`，**不带 `.js` 后缀**。
nginx 常配 `location ~ .*\.(js|css)$` 静态规则，带扩展名的请求不会进 PHP，直接 404。
（1.1.0 的 `device/heartbeat.js` 地址保留为兼容入口，但在上述 nginx 下不可用。）

新装项目若需要自定义阈值，发布配置文件：

```bash
php artisan vendor:publish --tag=google-authenticator-config
```

配置项见 `config/google-authenticator.php`：

```php
'single_login' => [
    'enabled'            => env('ADMIN_SINGLE_LOGIN', false),
    'cache_prefix'       => 'admin:device:',
    'cookie_name'        => 'admin_device_token',
    'token_ttl'          => 31536000,
    'cookie_lifetime'    => 525600,
    'heartbeat_interval' => 30,
    'kicked_message'     => '您的账号已在其他设备登录，当前设备已被强制下线，请重新登录。',
],

'login_guard' => [
    'enabled' => env('ADMIN_LOGIN_GUARD', true),
    'account_attempts' => 5,
    'account_decay'    => 900,
    'account_ban'      => 900,
    'account_total_attempts' => 20,
    'ip_attempts' => 30,
    'ip_decay'    => 900,
    'ip_ban'      => 3600,
    'failed_message' => '用户名、密码或验证码错误',
    'locked_message' => '登录失败次数过多，该账号已被临时锁定，请稍后再试',
],
```

> 关闭单设备登录时不会产生任何 Redis 写入，也不改变现有登录行为。

