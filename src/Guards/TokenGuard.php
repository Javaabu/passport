<?php

namespace Javaabu\Passport\Guards;

use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
use Javaabu\Passport\Traits\HasUserIdentifier;
use Laravel\Passport\TransientToken;

class TokenGuard extends \Laravel\Passport\Guards\TokenGuard
{
    use HasUserIdentifier;

    /**
     * Authenticate the incoming request via the token cookie.
     */
    protected function authenticateViaCookie(): ?Authenticatable
    {
        if (! $token = $this->getTokenViaCookie()) {
            return null;
        }

        // If this user exists, we will return this user and attach a "transient" token to
        // the user model. The transient token assumes it has all scopes since the user
        // is physically logged into the application via the application's interface.
        try {
            $user = $this->retrieveUserById($token['sub']);
        } catch (Exception) {
            return null;
        }

        return $user?->withAccessToken(new TransientToken);
    }
}
