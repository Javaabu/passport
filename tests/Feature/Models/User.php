<?php

namespace Javaabu\Passport\Tests\Feature\Models;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Laravel\Passport\HasApiTokens;

class User extends \Illuminate\Foundation\Auth\User
{
    use HasApiTokens;

    public function isActive(): Attribute
    {
        return Attribute::get(function () {
           return true;
        });
    }
}
