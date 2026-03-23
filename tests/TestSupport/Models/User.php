<?php

namespace Javaabu\Passport\Tests\TestSupport\Models;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Javaabu\Passport\Tests\TestSupport\Enums\UserStatuses;
use Javaabu\Passport\Traits\HasUserIdentifier;
use Laravel\Passport\HasApiTokens;

class User extends \Illuminate\Foundation\Auth\User
{
    use HasApiTokens;
    use HasUserIdentifier;

    protected $casts = [
        'status' => UserStatuses::class,
    ];

    public function isActive(): Attribute
    {
        return Attribute::get(function () {
           return $this->status === UserStatuses::APPROVED;
        });
    }

    public function getPassportCookieIdentifier(): string
    {
        return $this->makeUserIdentifier($this->getKey(), $this->getMorphClass());
    }
}
