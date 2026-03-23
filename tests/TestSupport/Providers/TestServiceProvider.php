<?php

namespace Javaabu\Passport\Tests\TestSupport\Providers;

use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Passport;

class TestServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     */
    public function boot()
    {
        $this->loadMigrationsFrom([
            __DIR__ . '/../database',
        ]);

        if (method_exists(Passport::class, 'enablePasswordGrant')) {
            Passport::enablePasswordGrant();
        }
    }

    /**
     * Register the application services.
     */
    public function register()
    {

    }
}
