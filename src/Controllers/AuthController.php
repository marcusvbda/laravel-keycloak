<?php

namespace marcusvbda\LaravelKeycloak\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use marcusvbda\LaravelKeycloak\Exceptions\KeycloakCallbackException;
use marcusvbda\LaravelKeycloak\Facades\KeycloakWeb;
use Spatie\ResponseCache\Facades\ResponseCache;

class AuthController extends Controller
{
    public function login()
    {
        ResponseCache::clear();
        $url = KeycloakWeb::getLoginUrl();
        KeycloakWeb::saveState();

        return redirect($url);
    }

    public function logout()
    {
        ResponseCache::clear();
        KeycloakWeb::forgetToken();
        $url = KeycloakWeb::getLogoutUrl();
        return redirect($url);
    }

    public function register()
    {
        ResponseCache::clear();
        $url = KeycloakWeb::getRegisterUrl();
        return redirect($url);
    }

    public function callback(Request $request)
    {
        ResponseCache::clear();
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
