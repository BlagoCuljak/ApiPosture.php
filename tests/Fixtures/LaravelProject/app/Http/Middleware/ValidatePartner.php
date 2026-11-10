<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;

class ValidatePartner
{
    public function handle($request, Closure $next)
    {
        if (empty($request->header('X-Partner'))) {
            return new JsonResponse(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
