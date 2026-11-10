<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Validation\UnauthorizedException;

class ValidateApiKey
{
    public function handle($request, Closure $next)
    {
        if (!hash_equals((string) config('services.key'), (string) $request->header('X-Key'))) {
            throw new UnauthorizedException();
        }

        return $next($request);
    }
}
