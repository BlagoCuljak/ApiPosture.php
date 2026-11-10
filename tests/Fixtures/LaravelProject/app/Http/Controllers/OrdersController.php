<?php

namespace App\Http\Controllers;

use Illuminate\Routing\Controllers\HasMiddleware;
use Illuminate\Routing\Controllers\Middleware;

class OrdersController extends Controller implements HasMiddleware
{
    public static function middleware(): array
    {
        return [new Middleware('auth', only: ['__invoke'])];
    }

    public function __invoke() {}
}
