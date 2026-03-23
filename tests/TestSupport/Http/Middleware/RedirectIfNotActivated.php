<?php

namespace Javaabu\Passport\Tests\TestSupport\Http\Middleware;

use Closure;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\Auth;
use Javaabu\Passport\Tests\TestSupport\Models\User;

class RedirectIfNotActivated
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  mixed  ...$guards
     * @return mixed
     *
     * @throws AuthorizationException
     */
    public function handle($request, Closure $next, ...$guards)
    {
        $guards = empty($guards) ? [null] : $guards;

        foreach ($guards as $guard) {
            if (Auth::guard($guard)->check()) {
                /** @var User $user */
                $user = Auth::guard($guard)->user();

                if (! $user->is_active) {
                    if ($request->expectsJson()) {
                        throw new AuthorizationException('Account not activated');
                    }

                    return redirect()->to('/verify');
                }
            }
        }

        return $next($request);
    }
}
