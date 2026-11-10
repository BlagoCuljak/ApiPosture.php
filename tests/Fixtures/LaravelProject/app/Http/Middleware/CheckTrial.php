<?php

namespace App\Http\Middleware;

use Closure;

// Rejects with 403 based on a request header only: a business rule, not authentication.
class CheckTrial
{
    public function handle($request, Closure $next)
    {
        if ($request->header('X-Plan') === 'expired') {
            abort(403, 'Trial expired');
        }

        return $next($request);
    }
}
