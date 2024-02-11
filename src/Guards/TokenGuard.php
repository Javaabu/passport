<?php

namespace Javaabu\Passport\Guards;

use Illuminate\Http\Request;
use Javaabu\Passport\Traits\HasUserIdentifier;
use Laravel\Passport\TransientToken;

class TokenGuard extends \Laravel\Passport\Guards\TokenGuard
{
    use HasUserIdentifier;

    /**
     * Authenticate the incoming request via the token cookie.
     *
     * @param  Request  $request
     * @return mixed
     */
    protected function authenticateViaCookie($request)
    {
        if (! $token = $this->getTokenViaCookie($request)) {
            return;
        }

        // If this user exists, we will return this user and attach a "transient" token to
        // the user model. The transient token assumes it has all scopes since the user
        // is physically logged into the application via the application's interface.
        if ($user = $this->retrieveUserById($token['sub'])) {
            return $user->withAccessToken(new TransientToken());
        }
    }
}
