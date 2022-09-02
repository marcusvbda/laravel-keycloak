<?php

namespace marcusvbda\LaravelKeycloak\Models;

use Auth;
use Illuminate\Contracts\Auth\Authenticatable;

class KeycloakUser implements Authenticatable
{
    protected $fillable = [
        'name',
        'email'
    ];

    protected $attributes = [];

    public function __construct(array $profile)
    {
        foreach ($profile as $key => $value) {
            if (in_array($key, $this->fillable)) {
                $this->attributes[ $key ] = $value;
            }
        }

        $this->id = $this->getKey();
    }

    public function __get(string $name)
    {
        return $this->attributes[ $name ] ?? null;
    }

    public function getKey()
    {
        return $this->email;
    }

    public function getAuthIdentifierName()
    {
        return 'email';
    }

    public function getAuthIdentifier()
    {
        return $this->email;
    }

    public function hasRole($roles, $resource = '')
    {
        return Auth::hasRole($roles, $resource);
    }

    public function getAuthPassword()
    {
        throw new \BadMethodCallException('Unexpected method [getAuthPassword] call');
    }

    public function getRememberToken()
    {
        throw new \BadMethodCallException('Unexpected method [getRememberToken] call');
    }

    public function setRememberToken($value)
    {
        throw new \BadMethodCallException('Unexpected method [setRememberToken] call');
    }
    
    public function getRememberTokenName()
    {
        throw new \BadMethodCallException('Unexpected method [getRememberTokenName] call');
    }
}
