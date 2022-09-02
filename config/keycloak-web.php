<?php

return [
    'acl_role_prefix' => env('ACL_ROLE_PREFIX', 'acl'),
    'base_url' => env('KEYCLOAK_BASE_URL', ''),
    'realm' => env('KEYCLOAK_REALM', 'master'),
    'realm_public_key' => env('KEYCLOAK_REALM_PUBLIC_KEY', null),
    'client_id' => env('KEYCLOAK_CLIENT_ID', null),
    'client_secret' => env('KEYCLOAK_CLIENT_SECRET', null),
    'cache_openid' => env('KEYCLOAK_CACHE_OPENID', false),
    'timeout_request' => env('KEYCLOAK_TIMEOUT_REQUEST',10),
    'retries_request' => env('KEYCLOAK_RETRIES_REQUEST',3),
    'redirect_url' => '/admin',
    'routes' => [
        'login' => 'login',
        'logout' => 'logout',
        'register' => 'register',
        'callback' => 'callback',
    ],
];
