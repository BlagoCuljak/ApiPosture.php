<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Core\Discovery;

use ApiPosture\Core\Analyzer\ProjectAnalyzer;
use ApiPosture\Core\Config\Configuration;
use ApiPosture\Core\Model\Endpoint;
use PHPUnit\Framework\TestCase;

/**
 * Cross-file Laravel resolution: route file mounts, middleware aliases/groups,
 * auth middleware detection by behaviour, and controller-declared protection.
 */
final class LaravelProjectContextTest extends TestCase
{
    /** @var array<string, array<string, Endpoint>> */
    private static array $scans = [];

    /**
     * @return array<string, Endpoint> keyed by "METHODS /route"
     */
    private function scan(string $fixture): array
    {
        if (!isset(self::$scans[$fixture])) {
            $result = (new ProjectAnalyzer(new Configuration()))->scan(__DIR__ . '/../../Fixtures/' . $fixture);
            $byRoute = [];
            foreach ($result->endpoints as $endpoint) {
                $byRoute[$endpoint->methodsString() . ' ' . $endpoint->route] = $endpoint;
            }
            self::$scans[$fixture] = $byRoute;
        }
        return self::$scans[$fixture];
    }

    private function endpoint(string $fixture, string $key): Endpoint
    {
        $routes = $this->scan($fixture);
        $this->assertArrayHasKey($key, $routes, 'Discovered: ' . implode(' | ', array_keys($routes)));
        return $routes[$key];
    }

    public function testRouteFilesAreMountedUnderProviderPrefixes(): void
    {
        $routes = array_keys($this->scan('LaravelProject'));

        $this->assertContains('GET /api/v2/orders', $routes, 'base_path() group mount');
        $this->assertContains('POST /users', $routes, 'require inside a group with empty prefix');
        $this->assertContains('DELETE /v1/coupons/{id}', $routes);
        $this->assertContains('POST /api/billing/invoices', $routes, 'module_path() resolves to the module routes file');
        $this->assertNotContains('GET /orders', $routes, 'unmounted path must not remain');
    }

    public function testMountMiddlewareAndGroupMembersAreApplied(): void
    {
        $endpoint = $this->endpoint('LaravelProject', 'GET /users');

        $this->assertContains('api', $endpoint->authorization->middleware);
        $this->assertContains('ApiRateLimiter', $endpoint->authorization->middleware, 'api group expands to its members');
        $this->assertFalse($endpoint->authorization->hasAuth);
    }

    public function testWebGroupExpandsToCsrfMiddleware(): void
    {
        $endpoint = $this->endpoint('LaravelProject', 'POST /profile');

        $this->assertContains('VerifyCsrfToken', $endpoint->authorization->middleware);
    }

    public function testControllerConstructorMiddlewareHonoursOnly(): void
    {
        $this->assertTrue($this->endpoint('LaravelProject', 'POST /users')->authorization->hasAuth);
        $this->assertTrue($this->endpoint('LaravelProject', 'PUT /users/{user}')->authorization->hasAuth, "['uses' => ...] action array");
        $this->assertFalse($this->endpoint('LaravelProject', 'GET /users')->authorization->hasAuth, 'index is outside only[]');
        $this->assertSame('controller', $this->endpoint('LaravelProject', 'POST /users')->authorization->inheritedFrom);
    }

    public function testHasMiddlewareStaticDeclaration(): void
    {
        $this->assertTrue($this->endpoint('LaravelProject', 'GET /api/v2/orders')->authorization->hasAuth);
    }

    public function testGateAuthorizeInActionCountsAsAuthorization(): void
    {
        $destroy = $this->endpoint('LaravelProject', 'DELETE /v1/coupons/{id}');
        $store = $this->endpoint('LaravelProject', 'POST /v1/coupons');

        $this->assertTrue($destroy->authorization->hasAuth);
        $this->assertContains('manage-coupons', $destroy->authorization->policies);
        $this->assertFalse($store->authorization->hasAuth);
        $this->assertSame('V1\CouponController', $destroy->controllerName, 'group namespace qualifies string controllers');
    }

    public function testInlineCheckCountsOnlyWithRealIdentity(): void
    {
        $this->assertTrue($this->endpoint('LaravelProject', 'POST /appointments/cancel')->authorization->hasAuth);
        $this->assertFalse(
            $this->endpoint('LaravelProject', 'POST /appointments/no-show')->authorization->hasAuth,
            'comparing two request-supplied ids is not authentication',
        );
    }

    public function testCustomMiddlewareClassifiedByBehaviour(): void
    {
        $this->assertTrue($this->endpoint('LaravelProject', 'POST /partner/orders')->authorization->hasAuth, '401 response');
        $this->assertTrue($this->endpoint('LaravelProject', 'POST /sync')->authorization->hasAuth, 'hash_equals + UnauthorizedException, action array middleware');
        $this->assertTrue($this->endpoint('LaravelProject', 'DELETE /staff/users/{id}')->authorization->hasAuth, '403 after inspecting the user');
        $this->assertFalse($this->endpoint('LaravelProject', 'POST /trial/extend')->authorization->hasAuth, '403 from a header rule is not auth');
        $this->assertFalse($this->endpoint('LaravelProject', 'POST /newsletter')->authorization->hasAuth, '422 validation is not auth');
    }

    public function testModuleRoutesStayPublicWithoutProtection(): void
    {
        $endpoint = $this->endpoint('LaravelProject', 'POST /api/billing/invoices');

        $this->assertFalse($endpoint->authorization->hasAuth);
        $this->assertNotNull($endpoint->handlerLocation);
        $this->assertStringEndsWith('Modules/Billing/app/Http/Controllers/InvoiceController.php', str_replace('\\', '/', $endpoint->handlerLocation->filePath));
    }

    public function testHandlerLocationPointsAtControllerMethod(): void
    {
        $endpoint = $this->endpoint('LaravelProject', 'DELETE /v1/coupons/{id}');

        $this->assertNotNull($endpoint->handlerLocation);
        $this->assertStringEndsWith('app/Http/Controllers/V1/CouponController.php', str_replace('\\', '/', $endpoint->handlerLocation->filePath));
        $this->assertSame(10, $endpoint->handlerLocation->lineNumber);
    }

    public function testLaravelElevenWithRoutingAndMiddlewareAliases(): void
    {
        $me = $this->endpoint('LaravelEleven', 'GET /api/v1/me');
        $feedback = $this->endpoint('LaravelEleven', 'POST /api/v1/feedback');

        $this->assertTrue($me->authorization->hasAuth, 'alias registered in bootstrap/app.php');
        $this->assertFalse($feedback->authorization->hasAuth);
        $this->assertContains('api', $feedback->authorization->middleware);
        $this->assertArrayHasKey('GET /', $this->scan('LaravelEleven'), 'web routes keep their path');
    }
}
