<?php

namespace App\Http\Middleware;

use Closure;

// No rejection of its own: hands the request to EnsureStaff, which enforces.
class ValidateGatewayOrStaff
{
    public function __construct(private readonly EnsureStaff $ensureStaff)
    {
    }

    public function handle($request, Closure $next)
    {
        if ($request->attributes->get('trusted')) {
            return $next($request);
        }

        return $this->ensureStaff->handle($request, $next);
    }
}
