<?php

namespace App\Http;

use App\Http\Middleware\ApiRateLimiter;
use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $middlewareGroups = [
        'web' => [
            \Illuminate\Session\Middleware\StartSession::class,
            \App\Http\Middleware\VerifyCsrfToken::class,
        ],
        'api' => [
            ApiRateLimiter::class,
            \Illuminate\Routing\Middleware\SubstituteBindings::class,
        ],
    ];

    protected $middlewareAliases = [
        'auth' => \App\Http\Middleware\Authenticate::class,
        'partner' => \App\Http\Middleware\ValidatePartner::class,
        'signed.key' => \App\Http\Middleware\ValidateApiKey::class,
        'trial' => \App\Http\Middleware\CheckTrial::class,
        'staff' => \App\Http\Middleware\EnsureStaff::class,
        'validate.email' => \App\Http\Middleware\ValidateEmail::class,
    ];
}
