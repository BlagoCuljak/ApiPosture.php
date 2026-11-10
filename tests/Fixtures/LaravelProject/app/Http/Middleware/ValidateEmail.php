<?php

namespace App\Http\Middleware;

use Closure;

class ValidateEmail
{
    public function handle($request, Closure $next)
    {
        if (!filter_var($request->input('email'), FILTER_VALIDATE_EMAIL)) {
            return response()->json(['email' => 'invalid'], 422);
        }

        return $next($request);
    }
}
