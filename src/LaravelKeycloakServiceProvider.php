<?php

namespace marcusvbda\LaravelKeycloak;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\ServiceProvider;
use marcusvbda\LaravelKeycloak\Auth\Guard\KeycloakWebGuard;
use marcusvbda\LaravelKeycloak\Auth\KeycloakWebUserProvider;
use marcusvbda\LaravelKeycloak\Services\KeycloakService;

class LaravelKeycloakServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $config = __DIR__ . '/../config/keycloak-web.php';
        $this->publishes([$config => config_path('keycloak-web.php')], 'config');
        $this->mergeConfigFrom($config, 'keycloak-web');

        Auth::provider('keycloak-users', function($app, array $config) {
            return new KeycloakWebUserProvider($config['model']);
        });
    }

    public function register()
    {
        Auth::extend('keycloak-web', function ($app, $name, array $config) {
            $provider = Auth::createUserProvider($config['provider']);
            return new KeycloakWebGuard($provider, $app->request);
        });

        $this->app->bind('keycloak-web', function($app) {
            return $app->make(KeycloakService::class);
        });
        
        $this->registerRoutes();

        $this->app->when(KeycloakService::class)->needs(ClientInterface::class)->give(function() {
            return new Client(Config::get('keycloak-web.guzzle_options', []));
        });
    }

    private function registerRoutes()
    {
        $defaults = [
            'login' => 'login',
            'logout' => 'logout',
            'register' => 'register',
            'callback' => 'callback',
        ];

        $routes = Config::get('keycloak-web.routes', []);
        $routes = array_merge($defaults, $routes);

        // Register Routes
        $router = $this->app->make('router');

        if (! empty($routes['login'])) {
            $router->middleware('web')->get($routes['login'], 'marcusvbda\LaravelKeycloak\Controllers\AuthController@login')->name('keycloak.login');
        }

        if (! empty($routes['logout'])) {
            $router->middleware('web')->get($routes['logout'], 'marcusvbda\LaravelKeycloak\Controllers\AuthController@logout')->name('keycloak.logout');
        }

        if (! empty($routes['register'])) {
            $router->middleware('web')->get($routes['register'], 'marcusvbda\LaravelKeycloak\Controllers\AuthController@register')->name('keycloak.register');
        }

        if (! empty($routes['callback'])) {
            $router->middleware('web')->get($routes['callback'], 'marcusvbda\LaravelKeycloak\Controllers\AuthController@callback')->name('keycloak.callback');
        }
    }
}
