<?php

namespace marcusvbda\LaravelKeycloak\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

class KeycloakWebUserProvider implements UserProvider
{
    protected $model;

    public function __construct($model)
    {
        $this->model = $model;
    }

    public function retrieveByCredentials(array $credentials)
    {
        $class = '\\'.ltrim($this->model, '\\');

        return new $class($credentials);
    }

    public function retrieveById($identifier)
    {
        throw new \BadMethodCallException('Unexpected method [retrieveById] call');
    }

    public function retrieveByToken($identifier, $token)
    {
        throw new \BadMethodCallException('Unexpected method [retrieveByToken] call');
    }
    public function updateRememberToken(Authenticatable $user, $token)
    {
        throw new \BadMethodCallException('Unexpected method [updateRememberToken] call');
    }

    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        throw new \BadMethodCallException('Unexpected method [validateCredentials] call');
    }
}
