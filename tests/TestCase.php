<?php

namespace Javaabu\Passport\Tests;

use Illuminate\Support\Facades\Config;
use Javaabu\Passport\Tests\Feature\Http\Controllers\Api\UsersController;
use \Javaabu\Passport\Tests\Feature\Models\User;
use Illuminate\Support\Facades\Route;
use Javaabu\Passport\Tests\Feature\OauthClientTest;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Javaabu\Passport\Tests\Feature\Providers\AppServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{

    public function setUp(): void
    {
        parent::setUp();

        $this->app['config']->set('app.key', 'base64:yWa/ByhLC/GUvfToOuaPD7zDwB64qkc/QkaQOrT5IpE=');

        $this->app['config']->set('session.serialization', 'php');

        $this->loadMigrations();

        $this->createUser();

        $this->registerRoutes();

        Passport::tokensCan([
            'read' => 'Read',
            'write' => 'Write',
        ]);

        Passport::cookie('api_token');


        Config::set('auth.guards.api', [
            'driver' => 'passport',
            'provider' => 'users',
        ]);
    }

    public function loadMigrations(): void
    {
        $this->loadLaravelMigrations();
        $this->loadMigrationsFrom(__DIR__ . '/../vendor/laravel/passport/database/migrations');
    }

    protected function getPackageProviders($app): array
    {
        return [
            \Javaabu\Passport\PassportServiceProvider::class,
            AppServiceProvider::class,
        ];
    }

    public function createUser(): void
    {
        $user = new User();
        $user->name = 'TestUser';
        $user->email = 'admin@example.com';
        $user->password = bcrypt('password');
        $user->save();
    }

    public function getUser(): User
    {
        return User::first();
    }

    protected function getClientAccessToken(array $scopes = ['read', 'write']): mixed
    {
        return $this->getAccessToken('client_credentials', $scopes);
    }

    protected function getAccessToken(string $grant_type = 'client_credentials', array $scopes = ['read', 'write'], array $params = [], Client $client = null)
    {
        if (empty($client)) {
            // create a new client
            $user = $this->getUser();
            $client = (new ClientRepository())->create(
                $user->id,
                'Test Client',
                'http://localhost'
            );
        }

        $request_params = array_merge([
            'client_id'     => $client->id,
            'client_secret' => $client->secret,
            'grant_type'    => $grant_type,
            'scope'         => implode(' ', $scopes),
        ], $params);

        // make the request
        $response = $this->json('post', '/oauth/token', $request_params)
            ->assertStatus(200)
            ->assertJsonStructure([
                'token_type',
                'expires_in',
                'access_token',
            ]);

        return ($response->json())['access_token'];
    }

    public function registerRoutes(): void
    {
        Route::middleware('oauth.client:read')
            ->group(function () {
                if (app()->runningUnitTests()) {
                    Route::get('test', function () {
                        return response()->json('It works');
                    });
                }
            });
    }
}
