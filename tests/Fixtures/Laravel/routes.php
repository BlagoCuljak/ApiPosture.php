<?php

use Illuminate\Support\Facades\Route;

// Public routes (no auth)
Route::get('/api/status', [StatusController::class, 'index']);
Route::get('/api/health', [HealthController::class, 'check']);

// Auth-protected routes
Route::middleware(['auth:sanctum'])->group(function () {
    Route::get('/api/users', [UserController::class, 'index']);
    Route::post('/api/users', [UserController::class, 'store']);
    Route::put('/api/users/{id}', [UserController::class, 'update']);
    Route::delete('/api/users/{id}', [UserController::class, 'destroy']);
});

// Role-protected routes
Route::middleware(['auth', 'role:admin'])->group(function () {
    Route::get('/api/admin/dashboard', [AdminController::class, 'dashboard']);
    Route::post('/api/admin/settings', [AdminController::class, 'updateSettings']);
});

// Guest-marked routes (explicit public intent)
Route::middleware(['guest'])->group(function () {
    Route::post('/api/auth/login', [AuthController::class, 'login']);
    Route::post('/api/auth/register', [AuthController::class, 'register']);
});

// Unprotected write endpoint (critical finding)
Route::post('/api/feedback', [FeedbackController::class, 'store']);

// Webhook endpoint
Route::post('/api/webhook/stripe', [WebhookController::class, 'handleStripe']);

// Admin route without auth (sensitive keyword + no auth)
Route::get('/api/debug/info', [DebugController::class, 'info']);

// Route with prefix
Route::prefix('/api/v2')->middleware(['auth'])->group(function () {
    Route::get('/products', [ProductController::class, 'index']);
    Route::post('/products', [ProductController::class, 'store']);
});
