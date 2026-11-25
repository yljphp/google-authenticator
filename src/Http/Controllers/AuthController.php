<?php

namespace Yljphp\GoogleAuthenticator\Http\Controllers;

use Encore\Admin\Auth\Database\Administrator;
use Encore\Admin\Facades\Admin;
use Encore\Admin\Form;
use Encore\Admin\Layout\Column;
use Encore\Admin\Layout\Content;
use Encore\Admin\Layout\Row;
use Encore\Admin\Widgets\Box;
use Illuminate\Http\Request;
use Encore\Admin\Controllers\AuthController as BaseAuthController;

use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Yljphp\GoogleAuthenticator\Services\DeviceService;
use Yljphp\GoogleAuthenticator\Services\LoginGuardService;

class AuthController extends BaseAuthController
{

	protected $loginView = 'google-authenticator::login';

	protected $googleView = 'google-authenticator::google';

	/**
	 * @var LoginGuardService
	 */
	protected $loginGuard;

	/**
	 * @var DeviceService
	 */
	protected $devices;

	/**
	 * {@inheritdoc}
	 */
	public function getLogin()
	{
		if ($this->guard()->check()) {
			return redirect($this->redirectPath());
		}

		return view($this->loginView);
	}

	/**
	 * Handle a login request.
	 *
	 * @param Request $request
	 *
	 * @return mixed
	 */
	public function postLogin(Request $request)
	{
		$this->loginValidator($request->all())->validate();

		$username = (string)$request->get($this->username());
		$password = (string)$request->input('password', '');
		$onecode  = (string)$request->input('onecode', '');
		$ip       = $request->ip();

		// 口令取出后立刻从请求里抹掉：
		// 应用的日志格式化器会记录完整请求体，不抹掉会把明文密码写进日志文件
		$this->scrubCredentials($request);

		$guard = $this->loginGuard();

		// 锁定期内直接拒绝，不再进入密码校验
		if ($guard->isLocked($username, $ip)) {
			Log::warning('admin_login_blocked', [
				'uid'     => 0,
				'account' => $username,
				'ip'      => $ip,
				'agent'   => $request->userAgent(),
			]);

			return back()->withInput()->withErrors([
				$this->username() => $guard->lockedMessage(),
			]);
		}

		$admin = Administrator::query()->where('username', $username)->first();

		// 用户不存在：走一次等价开销的哈希，抹平与"密码错误"的响应差异
		if (empty($admin)) {
			Hash::make($password);

			$guard->recordFailure($username, $ip, $request, 'user_not_found');

			return back()->withInput()->withErrors([
				$this->username() => $guard->failedMessage(),
			]);
		}

		if ($admin->is_open_google_auth) {
			// 开了验证但没有密钥时，验证码可被推算出来，必须拒绝登录
			if (empty($admin->google_auth)) {
				Log::warning('admin_login_google_secret_missing', [
					'uid'     => (int)$admin->getAuthIdentifier(),
					'account' => $username,
					'ip'      => $ip,
				]);

				$guard->recordFailure($username, $ip, $request, 'google_secret_missing');

				return back()->withInput()->withErrors([
					$this->username() => $guard->failedMessage(),
				]);
			}

			if (!$this->validOneCode($onecode) || !google_check_code((string)$admin->google_auth, $onecode, 1)) {
				$guard->recordFailure($username, $ip, $request, 'google_code_error');

				return back()->withInput()->withErrors([
					$this->username() => $guard->failedMessage(),
				]);
			}
		}

		$credentials = [$this->username() => $username, 'password' => $password];
		$remember = $request->get('remember', false);

		if ($this->guard()->attempt($credentials, $remember)) {
			$user = $this->guard()->user();

			$guard->recordSuccess($username, $ip, $request, (int)$user->getAuthIdentifier());

			$response = $this->sendLoginResponse($request);

			return $this->devices()->bind($request, $user, $remember, $response);
		}

		$guard->recordFailure($username, $ip, $request, 'password_error');

		return back()->withInput()->withErrors([
			$this->username() => $guard->failedMessage(),
		]);
	}

	/**
	 * 验证码必须是 6 位数字
	 */
	protected function validOneCode(string $onecode): bool
	{
		return (bool)preg_match('/^\d{6}$/', $onecode);
	}

	/**
	 * 从请求里抹掉口令与验证码，避免被日志记录
	 */
	protected function scrubCredentials(Request $request): void
	{
		foreach (['password', 'password_confirmation', 'onecode'] as $field) {
			$request->request->remove($field);
			$request->query->remove($field);
		}
	}

	protected function loginGuard(): LoginGuardService
	{
		if ($this->loginGuard === null) {
			$this->loginGuard = app(LoginGuardService::class);
		}

		return $this->loginGuard;
	}

	protected function devices(): DeviceService
	{
		if ($this->devices === null) {
			$this->devices = app(DeviceService::class);
		}

		return $this->devices;
	}

	public function google()
	{

		if (auth('admin')->user()->google_auth){

			$secret = auth('admin')->user()->google_auth;
//			$qrCodeUrl="otpauth://totp/".config("google.authenticatorname")."?secret=".$secret;//二维码中填充的内容
//			$createSecret = ['secret' =>$secret ,'codeurl'=>$qrCodeUrl];
			$createSecret = google_create_secret(32,$secret);

		}else
		{
			$createSecret = google_create_secret(32);
		}
		// 您自定义的参数，随表单返回
		$box = new Box('Google 验证绑定',view($this->googleView, ['createSecret' => $createSecret]) );
		$box->removable();
		$box->collapsable();
		$box->style('info');
		return $box->render();


	}

	public function getSetting(Content $content)
	{
		$form = $this->settingForm();
		$form->tools(
			function (Form\Tools $tools) {
				$tools->disableList();
				$tools->disableDelete();
				$tools->disableView();
			}
		);

		 return $content
            ->title(trans('admin.user_setting'))
            ->body($form->edit(Admin::user()->id));
	}


	public function googlePost(Request $request)
	{
		$onecode = (string) $request->onecode;
		if (empty($onecode) && strlen($onecode) != 6)
		{
			admin_toastr('请正确输入手机上google验证码 !','error');
			return response()->json(['message' => '请正确输入手机上google验证码 !','status'=> FALSE,]);
		}
		// google密钥，绑定的时候为生成的密钥；如果是绑定后登录，从数据库取以前绑定的密钥
		$google = $request->google;


		// 验证验证码和密钥是否相同
		if(google_check_code((string)$google,$onecode,1))
		{
			$admi_user = auth('admin')->user();
			$admi_user->google_auth = $google;
			$admi_user->save();
			admin_toastr('认证成功');
			return response()->json(['message' => '认证成功 !','status'=> TRUE,]);
		}
		else
		{
			admin_toastr('验证码错误，请输入正确的验证码 !','error');
			return response()->json(['message' => '验证码错误，请输入正确的验证码 !','status'=> FALSE,]);
		}
	}

	public function setGoogleAuth(Request $request)
	{
		$is_open_google_auth = $request->get('is_open_google_auth');

		auth('admin')->user()->is_open_google_auth = $is_open_google_auth;
		auth('admin')->user()->save();
		admin_toastr('设置成功');
		return response()->json(['message' => '设置成功 !','status'=> TRUE,]);
	}



	/**
	 * Model-form for user setting.
	 *
	 * @return Form
	 */
	protected function settingForm()
	{
		$class = config('admin.database.users_model');

		$form = new Form(new $class());

		$form->display('username', trans('admin.username'));
		$form->text('name', trans('admin.name'))->rules('required');
		$form->image('avatar', trans('admin.avatar'));
		$form->password('password', trans('admin.password'))->rules('confirmed|required');
		$form->password('password_confirmation', trans('admin.password_confirmation'))->rules('required')
			->default(function ($form) {
				return $form->model()->password;
			});

		$form->setAction(admin_url('auth/setting'));

		$form->ignore(['password_confirmation']);

		$form->saving(function (Form $form) {
			if ($form->password && $form->model()->password != $form->password) {
				$form->password = bcrypt($form->password);
			}
		});

		$form->saved(function () {
			admin_toastr(trans('admin.update_succeeded'));

			return redirect(admin_url('auth/setting'));
		});

		return $form;
	}
}
