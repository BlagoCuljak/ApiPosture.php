<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Route;

class RouteServiceProvider extends ServiceProvider
{
    protected $namespace = 'App\Http\Controllers';

    public function map(): void
    {
        Route::group([
            'prefix' => '',
            'middleware' => 'api',
            'namespace' => $this->namespace,
        ], function () {
            require base_path('routes/api.php');
        });

        Route::prefix('api/v2')
            ->middleware('api')
            ->namespace($this->namespace)
            ->group(base_path('routes/api-v2.php'));

        Route::middleware('web')->group(base_path('routes/web.php'));
    }
}
