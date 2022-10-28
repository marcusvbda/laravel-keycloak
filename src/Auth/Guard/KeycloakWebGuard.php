<?php

namespace marcusvbda\LaravelKeycloak\Auth\Guard;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use marcusvbda\LaravelKeycloak\Auth\KeycloakAccessToken;
use marcusvbda\LaravelKeycloak\Facades\KeycloakWeb;
use Illuminate\Contracts\Auth\UserProvider;

class KeycloakWebGuard implements Guard
{
    protected $user;

    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
    }

    public function check()
    {
        return (bool) $this->user();
    }

    public function hasUser()
    {
        return (bool) $this->user();
    }

    public function guest()
    {
        return !$this->check();
    }

    public function user()
    {
        if (empty($this->user)) {
            $this->authenticate();
        }

        return $this->user;
    }

    public function setUser(?Authenticatable $user)
    {
        $this->user = $user;
    }

    public function id()
    {
        $user = $this->user();
        return $user->id ?? null;
    }

    public function validate(array $credentials = [])
    {
        if (empty($credentials['access_token']) || empty($credentials['id_token'])) {
            return false;
        }

        $credentials['refresh_token'] = $credentials['refresh_token'] ?? '';
        KeycloakWeb::saveToken($credentials);

        return $this->authenticate();
    }

    public function authenticate()
    {
        $credentials = KeycloakWeb::retrieveToken();
        if (empty($credentials)) {
            return false;
        }

        $user = KeycloakWeb::getUserProfile($credentials);
        if (empty($user)) {
            KeycloakWeb::forgetToken();
            return false;
        }
        $user = $this->provider->retrieveByCredentials($user);
        $this->setUser($user);

        return true;
    }

    public function roles($resource = '')
    {
        if (empty($resource)) {
            $resource = Config::get('keycloak-web.client_id');
        }

        if (!$this->check()) {
            return false;
        }

        $token = KeycloakWeb::retrieveToken();

        if (empty($token) || empty($token['access_token'])) {
            return false;
        }

        $token = new KeycloakAccessToken($token);
        $token = $token->parseAccessToken();


        $resourceRoles = $token['roles'] ?? [];
        $resourceRoles = @$resourceRoles[$resource] ? $resourceRoles[$resource] : $resourceRoles;

        return $resourceRoles;
    }

    public function hasRole($roles, $resource = '')
    {
        $roles = $roles ?? [];
        $roles = is_array($roles) ? $roles : [$roles];

        $resourceRoles = $this->roles($resource);
        return empty(array_diff((array) $roles, $resourceRoles));
    }
}
