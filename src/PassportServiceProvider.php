<?php

namespace Javaabu\Passport;

use Illuminate\Auth\RequestGuard;
use Illuminate\Support\Facades\Auth;
use Javaabu\Passport\Guards\TokenGuard;
use Javaabu\Passport\Http\Middleware\AuthenticateOAuthClient;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\PassportServiceProvider as BasePassportServiceProvider;
use Laravel\Passport\PassportUserProvider;
use League\OAuth2\Server\ResourceServer;

class PassportServiceProvider extends BasePassportServiceProvider
{

    public function boot(): void
    {
        parent::boot();

        app('router')->aliasMiddleware('oauth.client', AuthenticateOAuthClient::class);
    }


    /**
     * Make an instance of the token guard.
     *
     * @param  array  $config
     * @return RequestGuard
     */
    protected function makeGuard(array $config): \Laravel\Passport\Guards\TokenGuard
    {

        return new TokenGuard(
            $this->app->make(ResourceServer::class),
            new PassportUserProvider(Auth::createUserProvider($config['provider']), $config['provider']),
            $this->app->make(ClientRepository::class),
            $this->app->make('encrypter'),
            $this->app->make('request')
        );
    }
}
