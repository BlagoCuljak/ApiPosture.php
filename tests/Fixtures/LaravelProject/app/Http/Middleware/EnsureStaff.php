<?php

namespace App\Http\Middleware;

use Closure;

class EnsureStaff
{
    public function handle($request, Closure $next)
    {
        if (!$request->user()?->is_staff) {
            return response()->json(['error' => 'Forbidden'], 403);
        }

        return $next($request);
    }
}
