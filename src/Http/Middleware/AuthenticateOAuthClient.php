<?php

namespace Javaabu\Passport\Http\Middleware;

use Closure;
use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Cookie\CookieValuePrefix;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Http\Request;
use Javaabu\Passport\Traits\HasUserIdentifier;
use Laravel\Passport\Client;
use Laravel\Passport\Exceptions\MissingScopeException;
use Laravel\Passport\Http\Middleware\CheckToken;
use Laravel\Passport\Passport;
use Laravel\Passport\TransientToken;

class AuthenticateOAuthClient
{
    use HasUserIdentifier;

    /**
     * The currently authenticated client.
     */
    protected ?Client $client = null;

    /**
     * Create a new token guard instance.
     *
     * @param  Encrypter  $encrypter
     * @return void
     */
    public function __construct(
        protected Encrypter $encrypter,
        protected Request $request,
    )
    {
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
                return app(CheckToken::class)->handle($request, $next, ...$scopes);
            } catch (AuthenticationException $e) {
                $this->authenticateViaCookie();

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

    /**
     * Get the token cookie via the incoming request.
     *
     * @return array<string, mixed>|null
     */
    protected function getTokenViaCookie(): ?array
    {
        // If we need to retrieve the token from the cookie, it'll be encrypted so we must
        // first decrypt the cookie and then attempt to find the token value within the
        // database. If we can't decrypt the value we'll bail out with a null return.
        try {
            $token = $this->decodeJwtTokenCookie();
        } catch (Exception) {
            return null;
        }

        // Token's expiration time is checked using the "exp" claim during decoding, but
        // legacy tokens may have an "expiry" claim instead of the standard "exp". So
        // we must manually check token's expiry, if the "expiry" claim is present.
        if (isset($token['expiry']) && time() >= $token['expiry']) {
            return null;
        }

        // We will compare the CSRF token in the decoded API token against the CSRF header
        // sent with the request. If they don't match then this request isn't sent from
        // a valid source and we won't authenticate the request for further handling.
        if (! Passport::$ignoreCsrfToken && ! $this->validCsrf($token)) {
            return null;
        }

        return $token;
    }

    /**
     * Decode and decrypt the JWT token cookie.
     *
     * @return array<string, mixed>
     */
    protected function decodeJwtTokenCookie(): array
    {
        $jwt = $this->request->cookie(Passport::cookie());

        return (array) JWT::decode(
            Passport::$decryptsCookies
                ? CookieValuePrefix::remove($this->encrypter->decrypt($jwt, Passport::$unserializesCookies))
                : $jwt,
            new Key(Passport::tokenEncryptionKey($this->encrypter), 'HS256')
        );
    }

    /**
     * Determine if the CSRF / header are valid and match.
     *
     * @param  array<string, mixed>  $token
     */
    protected function validCsrf(array $token): bool
    {
        $requestToken = $this->getTokenFromRequest();

        return isset($token['csrf']) &&
            is_string($requestToken) &&
            hash_equals($token['csrf'], $requestToken);
    }

    /**
     * Get the CSRF token from the request.
     */
    protected function getTokenFromRequest(): ?string
    {
        $token = $this->request->header('X-CSRF-TOKEN');

        if (! $token && $header = $this->request->header('X-XSRF-TOKEN')) {
            try {
                $token = CookieValuePrefix::remove($this->encrypter->decrypt($header, static::serialized()));
            } catch (DecryptException) {
                $token = null;
            }
        }

        return $token;
    }

    public function setRequest(Request $request): static
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Determine if the cookie contents should be serialized.
     */
    public static function serialized(): bool
    {
        return EncryptCookies::serialized('XSRF-TOKEN');
    }

    /**
     * Set the client for the current request.
     */
    public function setClient(Client $client): static
    {
        $this->client = $client;

        return $this;
    }
}
