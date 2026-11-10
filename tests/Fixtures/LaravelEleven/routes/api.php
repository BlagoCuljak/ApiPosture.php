<?php

use App\Http\Controllers\MeController;
use Illuminate\Support\Facades\Route;

Route::get('/me', [MeController::class, 'show'])->middleware('tenant');
Route::post('/feedback', [MeController::class, 'feedback']);
