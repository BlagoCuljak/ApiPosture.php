<?php

use App\Http\Controllers\OrdersController;
use Illuminate\Support\Facades\Route;

Route::get('/orders', OrdersController::class);
