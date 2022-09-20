<?php

namespace marcusvbda\LaravelKeycloak\Services;

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use marcusvbda\LaravelKeycloak\Auth\KeycloakAccessToken;
use Illuminate\Support\Facades\Http;

class KeycloakService
{
    const KEYCLOAK_SESSION = '_keycloak_token';
    const KEYCLOAK_SESSION_STATE = '_keycloak_state';
    protected $baseUrl;
    protected $realm;
    protected $clientId;
    protected $clientSecret;
    protected $openid;
    protected $cacheOpenid;
    protected $callbackUrl;
    protected $redirectLogout;
    protected $state;
    protected $timeoutRequest;
    protected $retriesRequest;
    protected $cacheLifetime;

    public function __construct()
    {
        if (is_null($this->retriesRequest)) {
            $this->retriesRequest = config('keycloak-web.retries_request');
        }

        if (is_null($this->timeoutRequest)) {
            $this->timeoutRequest = config('keycloak-web.timeout_request');
        }

        if (is_null($this->baseUrl)) {
            $this->baseUrl = trim(config('keycloak-web.base_url'), '/');
        }

        if (is_null($this->realm)) {
            $this->realm = config('keycloak-web.realm');
        }

        if (is_null($this->clientId)) {
            $this->clientId = config('keycloak-web.client_id');
        }

        if (is_null($this->clientSecret)) {
            $this->clientSecret = config('keycloak-web.client_secret');
        }

        if (is_null($this->cacheOpenid)) {
            $this->cacheOpenid = config('keycloak-web.cache_openid', false);
        }

        if (is_null($this->callbackUrl)) {
            $this->callbackUrl = route('keycloak.callback');
        }

        if (is_null($this->redirectLogout)) {
            $this->redirectLogout = config('keycloak-web.redirect_logout');
        }

        if (is_null($this->cacheLifetime)) {
            $this->cacheLifetime = config('keycloak-web.cache_lifetime');
        }


        $this->state = $this->generateRandomState();
    }

    public function getLoginUrl()
    {
        $url = $this->getOpenIdValue('authorization_endpoint');
        $params = [
            'scope' => 'openid',
            'response_type' => 'code',
            'client_id' => $this->getClientId(),
            'redirect_uri' => $this->callbackUrl,
            'state' => $this->getState(),
        ];

        return $this->buildUrl($url, $params);
    }

    public function getLogoutUrl()
    {
        $url = $this->getOpenIdValue('end_session_endpoint');

        if (empty($this->redirectLogout)) {
            $this->redirectLogout = url('/');
        }

        $params = [
            'client_id' => $this->getClientId(),
            'redirect_uri' => $this->redirectLogout,
        ];

        return $this->buildUrl($url, $params);
    }

    public function getRegisterUrl()
    {
        $url = $this->getLoginUrl();
        return str_replace('/auth?', '/registrations?', $url);
    }

    public function getAccessToken($code)
    {
        $url = $this->getOpenIdValue('token_endpoint');
        $params = [
            'code' => $code,
            'client_id' => $this->getClientId(),
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->callbackUrl,
        ];

        if (!empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {

            $response = Http::timeout($this->timeoutRequest)->retry($this->retriesRequest, $this->timeoutRequest)->asForm()->post($url, $params);

            if ($response->status() === 200) {
                $token = $response->json();
            }
        } catch (\Exception $e) {
            $this->logException($e);
        }

        return $token;
    }

    public function refreshAccessToken($credentials)
    {
        if (empty($credentials['refresh_token'])) {
            return [];
        }

        $url = $this->getOpenIdValue('token_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'grant_type' => 'refresh_token',
            'refresh_token' => $credentials['refresh_token'],
            'redirect_uri' => $this->callbackUrl,
        ];

        if (!empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = Http::timeout($this->timeoutRequest)->retry($this->retriesRequest, $this->timeoutRequest)->asForm()->post($url, $params);

            if ($response->status() === 200) {
                $token = $response->json();
            }
        } catch (\Exception $e) {
            $this->logException($e);
        }

        return $token;
    }

    public function invalidateRefreshToken($refreshToken)
    {
        $url = $this->getOpenIdValue('end_session_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'refresh_token' => $refreshToken,
        ];

        if (!empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        try {
            $response = Http::timeout($this->timeoutRequest)->retry($this->retriesRequest, $this->timeoutRequest)->asForm()->post($url, $params);
            return $response->status() === 204;
        } catch (\Exception $e) {
            $this->logException($e);
        }

        return false;
    }

    public function getUserProfile($credentials)
    {
        $credentials = $this->refreshTokenIfNeeded($credentials);
        $user = [];
        try {
            $token = new KeycloakAccessToken($credentials);

            if (empty($token->getAccessToken())) {
                throw new \Exception('Access Token is invalid.');
            }

            $claims = array(
                'aud' => $this->getClientId(),
                'iss' => $this->getOpenIdValue('issuer'),
            );

            $token->validateIdToken($claims);
            $url = $this->getOpenIdValue('userinfo_endpoint');
            $headers = [
                'Authorization' => 'Bearer ' . $token->getAccessToken(),
                'Accept' => 'application/json',
            ];

            $user = Cache::remember(md5($token->getAccessToken()) . "-user-info", $token->getLifetimeToken(), function () use ($token, $url, $headers) {
                $response = Http::timeout($this->timeoutRequest)->retry($this->retriesRequest, $this->timeoutRequest)->withHeaders($headers)->get($url);
                if ($response->status() !== 200) {
                    throw new \Exception('Was not able to get userinfo (not 200)');
                }

                $user = $response->getBody()->getContents();
                $token->validateSub($user['sub'] ?? '');
                return json_decode($user, true);
            });
        } catch (\Exception $e) {
            $this->logException($e);
        } catch (Exception $e) {
            Log::error('[Keycloak Service] ' . print_r($e->getMessage(), true));
        }

        return $user;
    }

    public function retrieveToken()
    {
        return session()->get(self::KEYCLOAK_SESSION);
    }

    public function saveToken($credentials)
    {
        session()->put(self::KEYCLOAK_SESSION, $credentials);
        session()->save();
    }

    public function forgetToken()
    {
        session()->forget(self::KEYCLOAK_SESSION);
        session()->save();
    }

    public function validateState($state)
    {
        $challenge = session()->get(self::KEYCLOAK_SESSION_STATE);
        return (!empty($state) && !empty($challenge) && $challenge === $state);
    }

    public function saveState()
    {
        session()->put(self::KEYCLOAK_SESSION_STATE, $this->state);
        session()->save();
    }

    public function forgetState()
    {
        session()->forget(self::KEYCLOAK_SESSION_STATE);
        session()->save();
    }

    public function buildUrl($url, $params)
    {
        $parsedUrl = parse_url($url);
        if (empty($parsedUrl['host'])) {
            return trim($url, '?') . '?' . Arr::query($params);
        }

        if (!empty($parsedUrl['port'])) {
            $parsedUrl['host'] .= ':' . $parsedUrl['port'];
        }

        $parsedUrl['scheme'] = (empty($parsedUrl['scheme'])) ? 'https' : $parsedUrl['scheme'];
        $parsedUrl['path'] = (empty($parsedUrl['path'])) ? '' : $parsedUrl['path'];

        $url = $parsedUrl['scheme'] . '://' . $parsedUrl['host'] . $parsedUrl['path'];
        $query = [];

        if (!empty($parsedUrl['query'])) {
            $parsedUrl['query'] = explode('&', $parsedUrl['query']);

            foreach ($parsedUrl['query'] as $value) {
                $value = explode('=', $value);

                if (count($value) < 2) {
                    continue;
                }

                $key = array_shift($value);
                $value = implode('=', $value);

                $query[$key] = urldecode($value);
            }
        }

        $query = array_merge($query, $params);

        return $url . '?' . Arr::query($query);
    }

    protected function getClientId()
    {
        return $this->clientId;
    }

    protected function getState()
    {
        return $this->state;
    }

    protected function getOpenIdValue($key)
    {
        if (!$this->openid) {
            $this->openid = $this->getOpenIdConfiguration();
        }

        return Arr::get($this->openid, $key);
    }

    protected function getOpenIdConfiguration()
    {
        $cacheKey = 'keycloak_web_guard_openid-' . $this->realm . '-';
        return Cache::remember($cacheKey . "-openid",  $this->cacheLifetime, function () use ($cacheKey) {
            $cacheKey .= md5($this->baseUrl);
            if ($this->cacheOpenid) {
                $configuration = Cache::get($cacheKey, []);
                if (!empty($configuration)) {
                    return $configuration;
                }
            }

            $url = $this->baseUrl . '/realms/' . $this->realm;
            $url = $url . '/.well-known/openid-configuration';

            $configuration = [];

            try {
                $response = Http::timeout($this->timeoutRequest)->retry($this->retriesRequest, $this->timeoutRequest)->get($url);
                if ($response->status() === 200) {
                    $configuration = $response->getBody()->getContents();
                    $configuration = json_decode($configuration, true);
                }
            } catch (\Exception $e) {
                $this->logException($e);

                throw new \Exception('[Keycloak Error] It was not possible to load OpenId configuration: ' . $e->getMessage());
            }

            if ($this->cacheOpenid) {
                Cache::put($cacheKey, $configuration);
            }

            return $configuration;
        });
    }

    public function getBearerToken()
    {
        return $this->refreshTokenIfNeeded($this->retrieveToken());
    }

    protected function refreshTokenIfNeeded($credentials)
    {
        $cacheKey = md5(data_get($credentials, "access_token", ""));
        if (!is_array($credentials) || empty($credentials['access_token']) || empty($credentials['refresh_token'])) {
            return $credentials;
        }

        $token = new KeycloakAccessToken($credentials);
        if (!$token->hasExpired()) {
            return $credentials;
        }

        Cache::forget($cacheKey . "-user-info");
        $credentials = $this->refreshAccessToken($credentials);

        if (empty($credentials['access_token'])) {
            $this->forgetToken();
            return [];
        }

        static::saveToken($credentials);
        return $credentials;
    }

    protected function logException(\Exception $e)
    {
        if (!method_exists($e, 'getResponse') || empty($e->getResponse())) {
            Log::error('[Keycloak Service] ' . $e->getMessage());
            return;
        }

        $error = [
            'request' => method_exists($e, 'getRequest') ? $e->getRequest() : '',
            'response' => $e->getResponse()->getBody()->getContents(),
        ];

        Log::error('[Keycloak Service] ' . print_r($error, true));
    }

    protected function generateRandomState()
    {
        return bin2hex(random_bytes(16));
    }
}
