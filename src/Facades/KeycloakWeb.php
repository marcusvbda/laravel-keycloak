<?php

namespace marcusvbda\LaravelKeycloak\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static getLoginUrl()
 * @method static getLogoutUrl()
 * @method static getAccessToken(string $code)
 * @method static getUserProfile(array $credentials)
 * @method static forgetToken()
 * @method static getBearerToken()
 */
class KeycloakWeb extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'keycloak-web';
    }
}
