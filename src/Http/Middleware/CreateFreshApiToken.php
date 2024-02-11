<?php

namespace Javaabu\Passport\Http\Middleware;

use Closure;
use Exception;
use Firebase\JWT\JWT;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Cookie\CookieValuePrefix;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Laravel\Passport\ApiTokenCookieFactory;
use Laravel\Passport\Passport;

class CreateFreshApiToken extends \Laravel\Passport\Http\Middleware\CreateFreshApiToken
{
    /**
     * Routes that a ignored
     *
     * @var array
     */
    protected $ignored_requests = [
        'admin.dynamic-css',
    ];

    /**
     * The encrypter implementation.
     *
     * @var Encrypter
     */
    protected $encrypter;

    /**
     * Create a new middleware instance.
     *
     * @param  ApiTokenCookieFactory  $cookieFactory
     * @param  Encrypter              $encrypter
     */
    public function __construct(
        ApiTokenCookieFactory $cookieFactory,
        Encrypter             $encrypter
    )
    {
        parent::__construct($cookieFactory);

        $this->encrypter = $encrypter;
    }

    /**
     * Handle an incoming request.
     *
     * @param  Request      $request
     * @param  Closure      $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = null)
    {
        $this->guard = $guard;

        $response = $next($request);

        if ($this->shouldReceiveFreshToken($request, $response)) {
            $user = $request->user($this->guard);
            $identifier = ($user && $user->is_active) ? $user->getPassportCookieIdentifier() : null;

            $response->withCookie($this->cookieFactory->make(
                $identifier,
                $request->session()->token()
            ));
        }

        return $response;
    }

    /**
     * Determine if the given request should receive a fresh token.
     *
     * @param  Request   $request
     * @param  Response  $response
     * @return bool
     */
    protected function shouldReceiveFreshToken($request, $response)
    {
        return $this->requestShouldReceiveFreshToken($request) &&
            (
                $this->responseShouldReceiveFreshToken($response) ||
                $this->authStatusHasChanged($request, $response)
            );
    }

    /**
     * Determine if the request should receive a fresh token.
     *
     * @param  Request  $request
     * @return bool
     */
    protected function requestShouldReceiveFreshToken($request)
    {
        $route_name = $request->route()->getName();

        return $request->isMethod('GET') &&
            !in_array($route_name, $this->ignored_requests);
    }


    /**
     * Check if the authentication status has changed from the previous request
     *
     * @param  Request   $request
     * @param  Response  $response
     * @return boolean
     */
    protected function authStatusHasChanged($request, $response)
    {
        // Already has a token cookie
        // But the cookie doesn't match the current auth status

        $user = $request->user($this->guard);
        $identifier = $user ? $user->getPassportCookieIdentifier() : null;

        return $this->alreadyContainsToken($response) &&
            ($identifier != $this->getCookieUserIdentifier($response));
    }

    /**
     * Check if the current cookie has a user defined
     *
     * @param $response
     * @return mixed
     */
    protected function getCookieUserIdentifier($response)
    {
        // If we need to retrieve the token from the cookie, it'll be encrypted so we must
        // first decrypt the cookie and then attempt to find the token value within the
        // database. If we can't decrypt the value we'll bail out with a false return.
        try {
            $token = $this->decodeJwtTokenCookie($response);
            return $token['sub'];
        } catch (Exception $e) {
            return null;
        }
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
}
