<?php

namespace Javaabu\Passport\Http\Middleware;

use Closure;
use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Cookie\CookieValuePrefix;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Http\Request;
use Laravel\Passport\Exceptions\MissingScopeException;
use Laravel\Passport\Http\Middleware\CheckClientCredentials;
use Laravel\Passport\Passport;

class AuthenticateOAuthClient
{
    /**
     * The encrypter implementation.
     *
     * @var Encrypter
     */
    protected $encrypter;

    /**
     * Create a new token guard instance.
     *
     * @param  Encrypter  $encrypter
     * @return void
     */
    public function __construct(
        Encrypter $encrypter
    )
    {
        $this->encrypter = $encrypter;
    }

    /**
     * Handle an incoming request.
     *
     * @param  Request   $request
     * @param  Closure   $next
     * @param  string[]  ...$scopes
     * @return mixed
     *
     * @throws AuthenticationException
     */
    public function handle($request, Closure $next, ...$scopes)
    {
        try {
            $api_guards = $this->getApiGuards();

            //first try normal authentication
            return app(Authenticate::class)->handle($request, function ($request) use ($next, $scopes) {

                // check if active
                if (!$request->user()->is_active) {
                    throw new AuthorizationException('Account not activated');
                }

                //check for scopes
                foreach ($scopes as $scope) {
                    if (!$request->user()->tokenCan($scope)) {
                        throw new MissingScopeException($scope);
                    }
                }

                return $next($request);
            }, ...$api_guards);
        } catch (AuthenticationException $e) {
            try {
                //authentication failed, try client auth
                return app(CheckClientCredentials::class)->handle($request, $next, ...$scopes);
            } catch (AuthenticationException $e) {
                $this->authenticateViaCookie($request);

                return $next($request);
            }
        }
    }

    /**
     * Get the passport guards
     */
    protected function getApiGuards(): array
    {
        return config('auth.passport_guards', ['api']);
    }

    /**
     * Authenticate the incoming request via the token cookie.
     *
     * @param  Request  $request
     * @return void
     */
    protected function authenticateViaCookie($request)
    {
        if (!$token = $this->getTokenViaCookie($request)) {
            throw new AuthenticationException();
        }
    }

    /**
     * Get the token cookie via the incoming request.
     *
     * @param  Request  $request
     * @return mixed
     */
    protected function getTokenViaCookie($request)
    {
        // If we need to retrieve the token from the cookie, it'll be encrypted so we must
        // first decrypt the cookie and then attempt to find the token value within the
        // database. If we can't decrypt the value we'll bail out with a null return.
        try {
            $token = $this->decodeJwtTokenCookie($request);
        } catch (Exception $e) {
            return;
        }

        // We will compare the CSRF token in the decoded API token against the CSRF header
        // sent with the request. If they don't match then this request isn't sent from
        // a valid source and we won't authenticate the request for further handling.
        if (!Passport::$ignoreCsrfToken && (!$this->validCsrf($token, $request) ||
                time() >= $token['expiry'])) {
            return;
        }

        return $token;
    }

    /**
     * Decode and decrypt the JWT token cookie.
     *
     * @param  Request  $request
     * @return array
     */
    protected function decodeJwtTokenCookie($request)
    {
        return (array)JWT::decode(
            CookieValuePrefix::remove($this->encrypter->decrypt($request->cookie(Passport::cookie()), Passport::$unserializesCookies)),
            new Key(Passport::tokenEncryptionKey($this->encrypter), 'HS256'),
        );
    }

    /**
     * Determine if the CSRF / header are valid and match.
     *
     * @param  array                     $token
     * @param  Request  $request
     * @return bool
     */
    protected function validCsrf($token, $request)
    {
        return isset($token['csrf']) && hash_equals(
                $token['csrf'],
                (string)$this->getTokenFromRequest($request)
            );
    }

    /**
     * Get the CSRF token from the request.
     *
     * @param  Request  $request
     * @return string
     */
    protected function getTokenFromRequest($request)
    {
        $token = $request->header('X-CSRF-TOKEN');

        if (!$token && $header = $request->header('X-XSRF-TOKEN')) {
            $token = CookieValuePrefix::remove($this->encrypter->decrypt($header, static::serialized()));
        }

        return $token;
    }

    /**
     * Determine if the cookie contents should be serialized.
     *
     * @return bool
     */
    public static function serialized()
    {
        return EncryptCookies::serialized('XSRF-TOKEN');
    }
}
