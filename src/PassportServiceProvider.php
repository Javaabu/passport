<?php

namespace Javaabu\Passport;

use Illuminate\Auth\RequestGuard;
use Illuminate\Support\Facades\Auth;
use Javaabu\Passport\Guards\TokenGuard;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider as BasePassportServiceProvider;
use Laravel\Passport\PassportUserProvider;
use Laravel\Passport\TokenRepository;
use League\OAuth2\Server\ResourceServer;

class PassportServiceProvider extends BasePassportServiceProvider
{
    /**
     * Make an instance of the token guard.
     *
     * @param  array  $config
     * @return RequestGuard
     */
    protected function makeGuard(array $config): RequestGuard
    {
        return new RequestGuard(function ($request) use ($config) {
            return (new TokenGuard(
                $this->app->make(ResourceServer::class),
                new PassportUserProvider(Auth::createUserProvider($config['provider']), $config['provider']),
                $this->app->make(TokenRepository::class),
                $this->app->make(ClientRepository::class),
                $this->app->make('encrypter'),
                $request
            ))->user();
        }, $this->app['request']);
    }
}
