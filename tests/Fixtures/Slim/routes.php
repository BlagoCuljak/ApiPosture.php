<?php

use Slim\App;

$app = new App();

// Public routes
$app->get('/api/status', function ($request, $response) {
    return $response->withJson(['status' => 'ok']);
});

$app->get('/api/health', function ($request, $response) {
    return $response->withJson(['healthy' => true]);
});

// Protected group
$app->group('/api/users', function ($group) {
    $group->get('', function ($request, $response) {
        return $response->withJson([]);
    });
    $group->post('', function ($request, $response) {
        // Create user
    });
    $group->put('/{id}', function ($request, $response) {
        // Update user
    });
    $group->delete('/{id}', function ($request, $response) {
        // Delete user
    });
})->add(new AuthMiddleware());

// Unprotected write endpoint
$app->post('/api/contact', function ($request, $response) {
    // Handle contact form
});

// Admin routes with JWT middleware
$app->group('/api/admin', function ($group) {
    $group->get('/dashboard', function ($request, $response) {
        return $response->withJson([]);
    });
    $group->post('/settings', function ($request, $response) {
        // Update settings
    });
})->add(new JwtAuthMiddleware());
