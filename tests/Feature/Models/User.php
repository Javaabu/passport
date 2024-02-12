<?php

namespace Javaabu\Passport\Tests\Feature\Models;

use Laravel\Passport\HasApiTokens;

class User extends \Illuminate\Foundation\Auth\User
{
    use HasApiTokens;

    
}