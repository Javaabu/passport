<?php

namespace Javaabu\Passport\Tests;

use Illuminate\Cookie\CookieValuePrefix;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use Javaabu\Passport\Http\Middleware\CreateFreshApiToken;
use Javaabu\Passport\Tests\TestSupport\Enums\UserStatuses;
use Javaabu\Passport\Tests\TestSupport\Models\User;
use Javaabu\Passport\Tests\TestSupport\Providers\TestServiceProvider;
use Laravel\Passport\ApiTokenCookieFactory;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Orchestra\Testbench\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{

    public function setUp(): void
    {
        parent::setUp();

        $this->app['config']->set('app.key', 'base64:yWa/ByhLC/GUvfToOuaPD7zDwB64qkc/QkaQOrT5IpE=');

        $this->app['config']->set('session.serialization', 'php');

        $this->createUser();

        $this->registerRoutes();

        //Passport::loadKeysFrom(__DIR__.'/keys');

        Config::set('passport.private_key', file_get_contents(__DIR__ . '/TestSupport/keys/oauth-private.key'));
        Config::set('passport.public_key', file_get_contents(__DIR__ . '/TestSupport/keys/oauth-public.key'));

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

    protected function getPackageProviders($app): array
    {
        return [
            \Javaabu\Passport\PassportServiceProvider::class,
            TestServiceProvider::class,
        ];
    }

    public function createUser(?string $email = null): User
    {
        $user = new User();
        $user->status = UserStatuses::APPROVED;
        $user->name = 'TestUser';
        $user->email = $email ?: 'admin@example.com';
        $user->password = bcrypt('password');
        $user->save();

        return $user;
    }

    protected function actingAsApiUser($email, $scopes = ['read', 'write'], $guard = null)
    {
        //find the user
        $user = is_object($email) ? $email : $this->getUser($email);

        if (! $guard) {
            $guard = 'api';
        }

        Passport::actingAs($user, $scopes, $guard);
    }

    public function getUser(?string $email = null): User
    {
        if ($email) {
            $user = User::where('email', $email)->first();

            if (! $user) {
                $user = $this->createUser($email);
            }
        } else {
            $user = User::first();
        }

        return $user ?: $this->createUser();
    }

    protected function getClientAccessToken(array $scopes = ['read', 'write']): mixed
    {
        return $this->getAccessToken('client_credentials', $scopes);
    }

    protected function getOAuthCookie($user)
    {
        $cookie_factory = new ApiTokenCookieFactory(app('config'), app('encrypter'));

        // initialize the CSRF Token
        session()->start();

        $identifier = ($user && $user->is_active) ? $user->getPassportCookieIdentifier() : null;

        $cookie = $cookie_factory->make($identifier ?: '', session()->token());

        return app('encrypter')->encrypt(
            CookieValuePrefix::create($cookie->getName(), app('encrypter')->getKey()).$cookie->getValue(),
            Passport::$unserializesCookies
        );
    }

    public function jsonApi($method, $uri, array $data = [], string $access_cookie = '', array $headers = [], array $cookies = [])
    {
        $files = $this->extractFilesFromDataArray($data);

        $content = json_encode($data);

        $headers = array_merge([
            'CONTENT_LENGTH' => mb_strlen($content, '8bit'),
            'CONTENT_TYPE' => 'application/json',
            'Accept' => 'application/json',
            'X-CSRF-TOKEN' => session()->token(),
        ], $headers);

        $cookies = array_merge([
            Passport::cookie() => $access_cookie,
        ], $cookies);

        return $this->call(
            $method,
            $uri,
            [],
            $cookies,
            $files,
            $this->transformHeadersToServerVars($headers),
            $content
        );
    }

    protected function getAccessToken(
        string $grant_type = 'client_credentials',
        array $scopes = ['read', 'write'],
        array $params = [],
        ?Client $client = null
    )
    {
        if (empty($client)) {
            // create a new client
            if ($grant_type === 'client_credentials') {
                $client = (new ClientRepository())->createClientCredentialsGrantClient(
                    'Test Client'
                );
            } else {
                $client = (new ClientRepository())->createPasswordGrantClient(
                    'Test Client',
                    'users'
                );
            }
        }

        $request_params = array_merge([
            'client_id'     => $client->id,
            'client_secret' => $client->plainSecret,
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

        Route::middleware([
            'auth:api',
            'active:api'
        ])
            ->group(function () {
                Route::get('users/profile', function (Request $request) {
                    return response()->json($request->user());
                });
            });

        Route::middleware([
            'web',
            CreateFreshApiToken::class,
            'auth:web'
        ])
            ->group(function () {
                Route::get('/verify', function (Request $request) {
                    return response()->json($request->user());
                });

                Route::middleware([
                    'active:web'
                ])->group(function () {
                    Route::get('/dashboard', function (Request $request) {
                        return response()->json($request->user());
                    });
                });
            });
    }
}
