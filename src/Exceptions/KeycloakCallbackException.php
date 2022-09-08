<?php

namespace marcusvbda\LaravelKeycloak\Exceptions;

class KeycloakCallbackException extends \RuntimeException
{
    public function __construct(string $error = '')
    {
        $message = '[Keycloak Error] ' . $error;

        parent::__construct($message);
    }
}
