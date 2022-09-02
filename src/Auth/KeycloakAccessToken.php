<?php

namespace marcusvbda\LaravelKeycloak\Auth;

use Exception;

class KeycloakAccessToken
{
    protected $accessToken;
    protected $refreshToken;
    protected $idToken;
    protected $expires;

    public function __construct($data = [])
    {
        $data = (array) $data;

        if (! empty($data['access_token'])) {
            $this->accessToken = $data['access_token'];
        }

        if (! empty($data['refresh_token'])) {
            $this->refreshToken = $data['refresh_token'];
        }

        if (! empty($data['id_token'])) {
            $this->idToken = $data['id_token'];
        }

        if (! empty($data['expires_in'])) {
            $this->expires = (int) $data['expires_in'];
        }
    }

    public function getAccessToken()
    {
        return $this->accessToken;
    }

    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    public function getIdToken()
    {
        return $this->idToken;
    }

    public function hasExpired()
    {
        $exp = $this->parseAccessToken();
        $exp = $exp['exp'] ?? '';

        return time() >= (int) $exp;
    }

    public function validateIdToken($claims)
    {
        $token = $this->parseIdToken();
        if (empty($token)) {
            throw new Exception('ID Token is invalid.');
        }

        $default = array(
            'exp' => 0,
            'aud' => '',
            'iss' => '',
        );

        $token = array_merge($default, $token);
        $claims = array_merge($default, (array) $claims);

        if (time() >= (int) $token['exp']) {
            throw new Exception('ID Token already expired.');
        }

        if (empty($claims['iss']) || $claims['iss'] !== $token['iss']) {
            throw new Exception('Access Token has a wrong issuer: must contain issuer from OpenId.');
        }

        $audience = (array) $token['aud'];
        if (empty($claims['aud']) || ! in_array($claims['aud'], $audience, true)) {
            throw new Exception('Access Token has a wrong audience: must contain clientId.');
        }

        if (count($audience) > 1 && empty($token['azp'])) {
            throw new Exception('Access Token has a wrong audience: must contain azp claim.');
        }

        if (! empty($token['azp']) && $claims['aud'] !== $token['azp']) {
            throw new Exception('Access Token has a wrong audience: has azp but is not the clientId.');
        }
    }

    public function validateSub($userSub)
    {
        $sub = $this->parseIdToken();
        $sub = $sub['sub'] ?? '';

        return $sub === $userSub;
    }

    public function parseAccessToken()
    {
        return $this->parseToken($this->accessToken);
    }

    public function parseIdToken()
    {
        return $this->parseToken($this->idToken);
    }

    protected function parseToken($token)
    {
        if (! is_string($token)) {
            return [];
        }

        $token = explode('.', $token);
        $token = $this->base64UrlDecode($token[1]);

        return json_decode($token, true);
    }

    protected function base64UrlDecode($data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}