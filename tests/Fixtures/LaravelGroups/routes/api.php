<?php

use Illuminate\Support\Facades\Route;

Route::get('/health-check', fn () => 'ok');

Route::group(['middleware' => ['throttle:10,1']], function () {
    Route::post('/signup', [AuthController::class, 'signUp']);

    Route::middleware('auth:api')->prefix('auth')->group(function () {
        Route::put('/profile', [AuthController::class, 'updateProfile']);
    });
});

Route::group(['middleware' => ['throttle:20,1']], function () {
    Route::group(['prefix' => 'login'], function () {
        Route::post('/', [AuthController::class, 'login']);
    });
    Route::post('/reset-password', [AuthController::class, 'resetPassword'])->name('password.reset');
});

Route::group(['middleware' => 'gateway.handshake', 'prefix' => 'professional'], function () {
    Route::get('/delete/{hardDelete}', [DeleteController::class, 'destroy']);
});
