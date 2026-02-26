<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Core\Discovery;

use ApiPosture\Core\Discovery\LaravelEndpointDiscoverer;
use ApiPosture\Core\Model\Enums\HttpMethod;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;

final class LaravelEndpointDiscovererTest extends TestCase
{
    private LaravelEndpointDiscoverer $discoverer;
    private \PhpParser\Parser $parser;

    protected function setUp(): void
    {
        $this->discoverer = new LaravelEndpointDiscoverer();
        $this->parser = (new ParserFactory())->createForNewestSupportedVersion();
    }

    public function testSupportsLaravelRouteFile(): void
    {
        $code = '<?php Route::get("/api/test", [TestController::class, "index"]);';
        $ast = $this->parser->parse($code);
        $this->assertTrue($this->discoverer->supports($ast, 'routes/web.php'));
    }

    public function testDoesNotSupportPlainPhp(): void
    {
        $code = '<?php echo "hello";';
        $ast = $this->parser->parse($code);
        $this->assertFalse($this->discoverer->supports($ast, 'test.php'));
    }

    public function testDiscoversSimpleGetRoute(): void
    {
        $code = '<?php Route::get("/api/users", [UserController::class, "index"]);';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes/api.php');

        $this->assertCount(1, $endpoints);
        $this->assertEquals('/api/users', $endpoints[0]->route);
        $this->assertEquals([HttpMethod::GET], $endpoints[0]->methods);
        $this->assertEquals('UserController', $endpoints[0]->controllerName);
        $this->assertEquals('index', $endpoints[0]->actionName);
    }

    public function testDiscoversPostRoute(): void
    {
        $code = '<?php Route::post("/api/users", [UserController::class, "store"]);';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes/api.php');

        $this->assertCount(1, $endpoints);
        $this->assertEquals([HttpMethod::POST], $endpoints[0]->methods);
    }

    public function testDiscoversMultipleRoutes(): void
    {
        $code = '<?php
            Route::get("/api/users", [UserController::class, "index"]);
            Route::post("/api/users", [UserController::class, "store"]);
            Route::put("/api/users/{id}", [UserController::class, "update"]);
            Route::delete("/api/users/{id}", [UserController::class, "destroy"]);
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes/api.php');

        $this->assertCount(4, $endpoints);
    }

    public function testDetectsAuthMiddleware(): void
    {
        $code = '<?php
            Route::middleware(["auth:sanctum"])->group(function () {
                Route::get("/api/users", [UserController::class, "index"]);
            });
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes/api.php');

        $this->assertCount(1, $endpoints);
        $this->assertTrue($endpoints[0]->authorization->hasAuth);
    }

    public function testDetectsGuestMiddleware(): void
    {
        $code = '<?php
            Route::middleware(["guest"])->group(function () {
                Route::post("/api/login", [AuthController::class, "login"]);
            });
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes/api.php');

        $this->assertCount(1, $endpoints);
        $this->assertTrue($endpoints[0]->authorization->hasAllowAnonymous);
    }

    public function testDetectsRoleMiddleware(): void
    {
        $code = '<?php
            Route::middleware(["auth", "role:admin"])->group(function () {
                Route::get("/api/admin", [AdminController::class, "index"]);
            });
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes/api.php');

        $this->assertCount(1, $endpoints);
        $this->assertTrue($endpoints[0]->authorization->hasAuth);
        $this->assertContains('admin', $endpoints[0]->authorization->roles);
    }

    public function testNoAuthMiddlewareMeansPublic(): void
    {
        $code = '<?php Route::get("/api/status", [StatusController::class, "index"]);';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes/api.php');

        $this->assertCount(1, $endpoints);
        $this->assertFalse($endpoints[0]->authorization->hasAuth);
        $this->assertFalse($endpoints[0]->authorization->hasAllowAnonymous);
    }

    public function testControllerWithMiddleware(): void
    {
        $code = '<?php
            class UserController extends Controller
            {
                public function __construct()
                {
                    $this->middleware("auth");
                }

                public function index() {}
                public function store() {}
            }
        ';
        $ast = $this->parser->parse($code);
        $this->assertTrue($this->discoverer->supports($ast, 'app/Http/Controllers/UserController.php'));
    }

    public function testStringActionFormat(): void
    {
        $code = '<?php Route::get("/api/users", "UserController@index");';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes/api.php');

        $this->assertCount(1, $endpoints);
        $this->assertEquals('UserController', $endpoints[0]->controllerName);
        $this->assertEquals('index', $endpoints[0]->actionName);
    }

    public function testPatchRoute(): void
    {
        $code = '<?php Route::patch("/api/users/{id}", [UserController::class, "patch"]);';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes/api.php');

        $this->assertCount(1, $endpoints);
        $this->assertEquals([HttpMethod::PATCH], $endpoints[0]->methods);
    }

    public function testCanMiddleware(): void
    {
        $code = '<?php
            Route::middleware(["auth", "can:manage-users"])->group(function () {
                Route::get("/api/users", [UserController::class, "index"]);
            });
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes/api.php');

        $this->assertCount(1, $endpoints);
        $this->assertTrue($endpoints[0]->authorization->hasAuth);
        $this->assertContains('manage-users', $endpoints[0]->authorization->policies);
    }
}
