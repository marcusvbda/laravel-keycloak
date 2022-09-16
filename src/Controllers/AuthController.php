<?php

namespace marcusvbda\LaravelKeycloak\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use marcusvbda\LaravelKeycloak\Exceptions\KeycloakCallbackException;
use marcusvbda\LaravelKeycloak\Facades\KeycloakWeb;

class AuthController extends Controller
{
    public function login()
    {
        $url = KeycloakWeb::getLoginUrl();
        KeycloakWeb::saveState();

        return redirect($url);
    }

    public function logout()
    {
        KeycloakWeb::forgetToken();
        $url = KeycloakWeb::getLogoutUrl();
        return redirect($url);
    }

    public function register()
    {
        $url = KeycloakWeb::getRegisterUrl();
        return redirect($url);
    }

    public function callback(Request $request)
    {
        if (!empty($request->input('error'))) {
            $error = $request->input('error_description');
            $error = ($error) ?: $request->input('error');

            throw new KeycloakCallbackException($error);
        }

        $state = $request->input('state');
        if (empty($state) || !KeycloakWeb::validateState($state)) {
            return $this->logout();
        }

        $code = $request->input('code');
        if (!empty($code)) {
            $token = KeycloakWeb::getAccessToken($code);

            if (Auth::validate($token)) {
                $url = config('keycloak-web.redirect_url', '/admin');
                return redirect()->intended($url);
            }
        }

        return redirect(route('keycloak.login'));
    }
}
