<?php

namespace Encore\James;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Validator;
use Illuminate\Foundation\Auth\ThrottlesLogins;
use Illuminate\Validation\ValidationException;

class JamesController extends Controller
{
    use ThrottlesLogins;
    protected $maxAttempts = 3;
    protected $decayMinutes = 30;
    /**
     * Show the login page.
     *
     * @return \Illuminate\Contracts\View\Factory|Redirect|\Illuminate\View\View
     */
    public function getLogin()
    {
        if ($this->guard()->check()) {
            return redirect($this->redirectPath());
        }

        return view('login-captcha::index');
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
        // 先对密码解密
        $pwd = $this->rsa($request->password);
        $request['password'] = $pwd;
        try {
            // 判断登录失败是否超过$maxAttempts次，超过$decayMinutes分钟后，接触锁定
            if (method_exists($this, 'hasTooManyLoginAttempts') && $this->hasTooManyLoginAttempts($request)) {
                $this->fireLockoutEvent($request);
                return back()->withInput()->withErrors([
                    $this->username() => $this->sendLockoutResponseMessage($request),
                ]);
            }
            // 正常登录的话，进行validator
            $validator = Validator::make($request->all(), [
                $this->username()   => 'required',
                'password'          => 'required',
                'captcha'           => 'required|captcha',
            ], [
                $this->username().'.required' => '用户名必填',
                'password.required'           => '密码必填',
                'captcha.required'            => '验证码必填',
                'captcha.captcha'             => '验证码错误',
            ]);
            // 验证错误，抛出错误信息
            if ($validator->fails()) {
                return back()->withInput()->withErrors($validator);
            }
            // 验证正确，就去验证账号、密码是否有错误
            $credentials = $request->only([$this->username(), 'password']);
            $remember = $request->get('remember', false);
            // 账号密码正确
            if ($this->guard()->attempt($credentials, $remember)) {
                $res = $this->sendLoginResponse($request);
                $this->clearLoginAttempts($request);
                return $res;
            }
            // 账号、密码错误，计数+1
            $this->incrementLoginAttempts($request);
            $num = $this->limiter()->attempts($this->throttleKey($request));
            $is_num = $this->maxAttempts - $num;
            return back()->withInput()->withErrors([
                $this->username()  => $is_num == 0 ? $this->sendLockoutResponseMessage($request):$this->getFailedLoginMessage().', 你还有'.$is_num.'次机会',
            ]);
        }catch (ValidationException $validationException) {
            $message = $validationException->validator->getMessageBag()->getMessages();
            $str = '';
            if (isset($message['password'])) {
                $str = $message['password'];
            }
            return back()->withInput()->withErrors([
                $this->username() => $str,
            ]);
        }
    }

    public function rsa($after_encode_data) {
        $private_key = '-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCZD5mNWaQpxEwSU/WSFMilxJp+HLHgXQo1U93FOUwhX2+/MFde
w+yGxQw/1qoluctNJisH7Q6KIkcOM8ysSLNrZ6i5kAlhsFPHEV7VdIG4whK+2mp8
hxRsUOVn1IGOalSFF6HpRTYW+XpA2Lr3RMmHatjZec63vDLa4VJjpK/7nwIDAQAB
AoGAEiry2/9O6BI/wVEr7en/owWCHQQE7Q++HXRV94oEilWMqxHu3PW+hoSvHoi5
a37xLbghFXDC8Ax/iKUHX0/F1APczBmZoDqMzDPcXvbsJEUP2B2kwB68XT1LCd5d
k8s7CClNlgxR7Ukpk82XAzfDsrocizh0Zc1ctEH4/Oe7iDkCQQDGcZtLI1J/fSMl
sxhgUyszyNWXs48pwJbKz5DZTyzhSZOuk8QU+Gtnx8QVjYD88NrTPgqCcGW4qZDX
R41jN0Y1AkEAxXRUlska3iMQPFhaRqky6tu5wbcZesxQrlLyWSupi/o2WAyvipwy
uVME5uPZxbGP3mqNgpYonz7cftQlYOKlAwJAdurTfcZwBJgPvOLDI84TIJgkbyEa
FJIliumxypeotGSsDDzejxaC/pD2j1fZyTnoWBhgoeQLAQsUEf3920vfVQJAcabF
0YyrlFSmUbWhMK7PCfOy9ddIKTBU+CHyMHU7P8CjawbSO3wwjg9E8QkRHgNYBfNa
xGFdvFtYWwANC7kotQJATaljqR8D8aVxLKsF4XJyiE2OeuLJDTsKbFjD6dNEJekH
buIPqTkZr4D6nZ2Lx2j1B+rbp+4MM2X1z3pv/IXRkg==
-----END RSA PRIVATE KEY-----
';
        openssl_private_decrypt(
            base64_decode($after_encode_data),
            $decode_result,
            $private_key
        );

        return $decode_result;
    }

    /**
     * @return string|\Symfony\Component\Translation\TranslatorInterface
     */
    protected function getFailedLoginMessage()
    {
        return Lang::has('auth.failed')
            ? trans('auth.failed')
            : 'These credentials do not match our records.';


    }

    /**
     * Get the post login redirect path.
     *
     * @return string
     */
    protected function redirectPath()
    {
        if (method_exists($this, 'redirectTo')) {
            return $this->redirectTo();
        }

        return property_exists($this, 'redirectTo') ? $this->redirectTo : config('admin.route.prefix');
    }

    /**
     * Send the response after the user was authenticated.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return \Illuminate\Http\Response
     */
    protected function sendLoginResponse(Request $request)
    {
        admin_toastr(trans('admin.login_successful'));

        $request->session()->regenerate();

        return redirect()->intended($this->redirectPath());
    }

    /**
     * Get the login username to be used by the controller.
     *
     * @return string
     */
    protected function username()
    {
        return 'username';
    }

    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\StatefulGuard
     */
    protected function guard()
    {
        return Auth::guard('admin');
    }

    protected function sendLockoutResponseMessage(Request $request) {
        $seconds = $this->limiter()->availableIn($this->throttleKey($request));
        $min = $this->decayMinutes();
        return ['登录过于频繁，'.ceil($seconds / 60).'分钟后重试'];
    }
}