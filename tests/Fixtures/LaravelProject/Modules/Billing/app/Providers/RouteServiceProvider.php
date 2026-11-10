<?php

namespace Modules\Billing\Providers;

use Illuminate\Support\Facades\Route;

class RouteServiceProvider
{
    protected string $name = 'Billing';

    public function map(): void
    {
        Route::middleware('api')->prefix('api')->group(module_path($this->name, '/routes/api.php'));
    }
}
