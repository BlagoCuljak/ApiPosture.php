<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;

class TenantAuth
{
    public function handle($request, Closure $next)
    {
        if ($request->bearerToken() === null) {
            throw new AuthenticationException();
        }

        return $next($request);
    }
}
