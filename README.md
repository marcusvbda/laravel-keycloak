## The flow

1. User access a guarded route and is redirected to Keycloak login.
1. User signin and obtains a code.
1. He's redirected to callback page and we change the code for a access token.
1. We store it on session and validate user.
1. User is logged.
1. We redirect the user to "redirect_url" route (see config) or the intended one.

## Install

Require the package

```
composer require marcusvbda/laravel-keycloak
```

If you want to change routes or the default values for Keycloak, publish the config file:

```
php artisan vendor:publish  --provider="marcusvbda/laravel-keycloak\LaravelKeycloakServiceProvider"

```

## Configuration

After publishing `config/keycloak-web.php` file, you can change the routes:

```php
'redirect_url' => '/admin',

'routes' => [
    'login' => 'login',
    'logout' => 'logout',
    'register' => 'register',
    'callback' => 'callback',
]
```

Change any value to change the URL.

Other configurations can be changed to have a new default value, but we recommend to use `.env` file:

*  `KEYCLOAK_BASE_URL`

The Keycloak Server url. Generally is something like: `https://your-domain.com/auth`.

*  `KEYCLOAK_REALM`

The Keycloak realm. The default is `master`.

*  `KEYCLOAK_REALM_PUBLIC_KEY`

The Keycloak Server realm public key (string).

In dashboard go to: Keycloak >> Realm Settings >> Keys >> RS256 >> Public Key.

*  `KEYCLOAK_CLIENT_ID`

Keycloak Client ID.

In dashboard go to: Keycloak >> Clients >> Installation.

*  `KEYCLOAK_CLIENT_SECRET`

Keycloak Client Secret. If empty we'll not send it to Token Endpoint.

In dashboard go to: Keycloak >> Clients >> Installation.

*  `KEYCLOAK_CACHE_OPENID`

We can cache the OpenId Configuration: it's a list of endpoints we require to Keycloak.

If you activate it, *remember to flush the cache* when change the realm or url.

Just add the options you would like as an array to the" to "Just add the options you would like to guzzle_options array on keycloak-web.php config file. For example:

## Laravel Auth

You should add Keycloak Web guard to your `config/auth.php`.

Just add **keycloak-web** to "driver" option on configurations you want.

As my default is web, I add to it:

```php
'guards' => [
    'web' => [
        'driver' => 'keycloak-web',
        'provider' => 'users',
    ],

    // ...
],
```

And change your provider config too:

```php
'providers' => [
    'users' => [
        'driver' => 'keycloak-users',
        'model' => marcusvbda\LaravelKeycloak\Models\KeycloakUser::class,
    ],

    // ...
]
```

**Note:** if you want use another User Model, check the FAQ *How to implement my Model?*.

## API

We implement the `Illuminate\Contracts\Auth\Guard`. So, all Laravel default methods will be available.

Ex: `Auth::user()` returns the authenticated user.

### My client is not public.

If your client is not public, you should provide a `KEYCLOAK_CLIENT_SECRET` on your `.env`.
