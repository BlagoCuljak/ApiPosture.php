<?php

// Routes registered by a test harness must not be reported as endpoints.
abstract class RouteRegistrationTestCase extends \PHPUnit\Framework\TestCase
{
    protected function registerRoutes(): void
    {
        $this->router->get('/test/admin', fn () => 'allowed');
        \Illuminate\Support\Facades\Route::post('/test/write', fn () => 'allowed');
    }
}
