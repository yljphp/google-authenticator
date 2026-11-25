<?php

namespace Yljphp\GoogleAuthenticator;

use Encore\Admin\Facades\Admin;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Yljphp\GoogleAuthenticator\Http\Controllers\DeviceController;
use Yljphp\GoogleAuthenticator\Http\Middleware\AdminDeviceCheckMiddleware;
use Yljphp\GoogleAuthenticator\Lib\GoogleAuthenticator as GoogleAuthenticatorLib;

class GoogleAuthenticatorServiceProvider extends ServiceProvider
{
    /**
     * {@inheritdoc}
     */
    public function boot(GoogleAuthenticator $extension)
    {
        if ($views = $extension->views()) {
            $this->loadViewsFrom($views, 'google-authenticator');
        }

        if ($this->app->runningInConsole() && $assets = $extension->assets()) {
            $this->publishes(
                [$assets => public_path('vendor/Yljphp/google-authenticator')],
                'google-authenticator'
            );
        }

        if ($this->app->runningInConsole()) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

            $this->publishes(
                [__DIR__.'/../config/google-authenticator.php' => config_path('google-authenticator.php')],
                'google-authenticator-config'
            );
        }

        // 单设备登录的设备校验，挂在 admin 中间件组末尾（admin.auth 之后，guard 内必有登录用户）
        $this->app['router']->aliasMiddleware('admin.device.check', AdminDeviceCheckMiddleware::class);
        $this->app['router']->pushMiddlewareToGroup('admin', 'admin.device.check');

        if (GoogleAuthenticator::boot()) {
            $this->app->booted(function () {
                GoogleAuthenticator::routes(__DIR__.'/../routes/web.php');
            });
        }

        $this->app->booted(function () {
            $this->registerDeviceRoutes();
        });

        if (config('google-authenticator.single_login.enabled', false)) {
            // 用 headerJs 而不是 Admin::js：Admin::js 在开启资源压缩发布后会被整包替换，自定义脚本会丢失
            // 路径不带 .js 后缀：nginx 常有 `location ~ .*\.(js|css)$` 静态规则，
            // 带扩展名的请求不会进 PHP，直接 404
            Admin::headerJs(admin_base_path('device/heartbeat'));
        }
    }

    /**
     * {@inheritdoc}
     */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../config/google-authenticator.php', 'google-authenticator');

        $this->app->bind('GoogleAuthenticator', function ($app) {
            return new GoogleAuthenticatorLib();
        });
    }

    /**
     * 单设备登录相关路由
     *
     * 单独注册，不放进 Extension::routes() 的 group：
     * 那个 group 已经带了一层 prefix，routes/web.php 内部又建了一层，会叠成 admin/admin
     *
     * 中间件里把 admin 组换成 admin.auth + admin.device.check：
     * admin 组里的 admin.log 会给每个 GET 写一条操作日志，心跳轮询每 30 秒一次扛不住
     */
    protected function registerDeviceRoutes(): void
    {
        $middleware = [];

        foreach ((array)config('admin.route.middleware', ['web']) as $item) {
            if ($item === 'admin') {
                $middleware[] = 'admin.auth';
                $middleware[] = 'admin.device.check';
                continue;
            }

            $middleware[] = $item;
        }

        if (!in_array('admin.auth', $middleware, true)) {
            $middleware[] = 'admin.auth';
            $middleware[] = 'admin.device.check';
        }

        Route::group([
            'prefix'     => config('admin.route.prefix'),
            'domain'     => config('admin.route.domain'),
            'middleware' => $middleware,
        ], function () {
            Route::get('device/status', DeviceController::class . '@status')->name('admin.device.status');
            // 心跳脚本走无扩展名路径，避免被 nginx 的静态资源规则（*.js）拦截成 404
            Route::get('device/heartbeat', DeviceController::class . '@heartbeat')->name('admin.device.heartbeat');
            // 兼容 1.1.0 的旧地址
            Route::get('device/heartbeat.js', DeviceController::class . '@heartbeat')->name('admin.device.heartbeat.js');
        });
    }
}
