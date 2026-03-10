<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Rules;

use ApiPosture\Rules\KnownPublicRoutes;
use PHPUnit\Framework\TestCase;

final class KnownPublicRoutesTest extends TestCase
{
    // -----------------------------------------------------------------
    // Auth entry points
    // -----------------------------------------------------------------

    public function testLoginIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/login'));
    }

    public function testLogoutIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/logout'));
    }

    public function testRegisterIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/register'));
    }

    public function testSigninIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/signin'));
    }

    public function testSignupIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/signup'));
    }

    // -----------------------------------------------------------------
    // OAuth2 endpoints
    // -----------------------------------------------------------------

    public function testAccessTokenIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/access_token'));
    }

    public function testAuthorizeIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/authorize'));
    }

    public function testDeviceAuthorizationIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/device_authorization'));
    }

    public function testOauthCallbackIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/oauth/callback'));
    }

    public function testApiTokenIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/api/token'));
    }

    // -----------------------------------------------------------------
    // Password / account flows
    // -----------------------------------------------------------------

    public function testForgotPasswordIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/forgot-password'));
    }

    public function testResetPasswordIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/reset-password'));
    }

    public function testResetPasswordWithTokenIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/reset-password/reset/{token}'));
    }

    public function testVerifyEmailIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/verify-email'));
    }

    public function testCheckEmailIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/check-email'));
    }

    public function testChangePasswordIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/change-password'));
    }

    public function testResetPasswordSubpathIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/reset-password/check-email'));
    }

    // -----------------------------------------------------------------
    // Infrastructure probes
    // -----------------------------------------------------------------

    public function testHealthIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/health'));
    }

    public function testHealthzIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/healthz'));
    }

    public function testLivenessIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/liveness'));
    }

    public function testPingIsPublic(): void
    {
        $this->assertTrue(KnownPublicRoutes::isKnownPublicEndpoint('/api/ping'));
    }

    // -----------------------------------------------------------------
    // NOT public — should not be exempt
    // -----------------------------------------------------------------

    public function testAdminIsNotPublic(): void
    {
        $this->assertFalse(KnownPublicRoutes::isKnownPublicEndpoint('/admin'));
    }

    public function testUsersIsNotPublic(): void
    {
        $this->assertFalse(KnownPublicRoutes::isKnownPublicEndpoint('/users'));
    }

    public function testDashboardIsNotPublic(): void
    {
        $this->assertFalse(KnownPublicRoutes::isKnownPublicEndpoint('/dashboard'));
    }

    public function testProfileIsNotPublic(): void
    {
        $this->assertFalse(KnownPublicRoutes::isKnownPublicEndpoint('/profile'));
    }

    public function testObjectManagerIsNotPublic(): void
    {
        // 'manage' substring inside 'object-manager' must NOT match
        $this->assertFalse(KnownPublicRoutes::isKnownPublicEndpoint('/object-manager.php'));
    }

    public function testDoctrineSvcIsNotPublic(): void
    {
        $this->assertFalse(KnownPublicRoutes::isKnownPublicEndpoint('doctrine'));
    }

    public function testJtiIsNotPublic(): void
    {
        $this->assertFalse(KnownPublicRoutes::isKnownPublicEndpoint('jti'));
    }

    public function testEmptyRouteIsNotPublic(): void
    {
        $this->assertFalse(KnownPublicRoutes::isKnownPublicEndpoint(''));
    }
}
