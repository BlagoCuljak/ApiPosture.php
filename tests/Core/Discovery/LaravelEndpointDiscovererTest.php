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


    /**
     * @return array<string, \ApiPosture\Core\Model\Endpoint>
     */
    private function discoverByRoute(string $code): array
    {
        $endpoints = $this->discoverer->discover($this->parser->parse($code), 'routes/api.php');
        $byRoute = [];
        foreach ($endpoints as $endpoint) {
            $byRoute[$endpoint->methodsString() . ' ' . $endpoint->route] = $endpoint;
        }
        return $byRoute;
    }

    public function testStaticRouteGroupWithMiddlewareArray(): void
    {
        $routes = $this->discoverByRoute('<?php
            Route::group(["middleware" => ["auth:api"], "prefix" => "account"], function () {
                Route::post("/logout", [AuthController::class, "logout"]);
            });
        ');

        $this->assertArrayHasKey('POST /account/logout', $routes);
        $this->assertTrue($routes['POST /account/logout']->authorization->hasAuth);
    }

    public function testStaticRouteGroupWithStringMiddlewareAndNoAuth(): void
    {
        $routes = $this->discoverByRoute('<?php
            Route::group(["middleware" => "throttle:10,1"], function () {
                Route::post("signup", [AuthController::class, "signUp"]);
            });
        ');

        $this->assertArrayHasKey('POST /signup', $routes);
        $this->assertFalse($routes['POST /signup']->authorization->hasAuth);
        $this->assertSame(['throttle:10,1'], $routes['POST /signup']->authorization->middleware);
    }

    public function testNestedMixedGroupsAccumulateContext(): void
    {
        $routes = $this->discoverByRoute('<?php
            Route::group(["middleware" => ["throttle:10,1"]], function () {
                Route::get("/list/countries", [CountriesController::class, "list"]);
                Route::middleware("auth:api")->prefix("auth")->group(function () {
                    Route::group(["prefix" => "me"], function () {
                        Route::put("/profile", [AuthController::class, "updateProfile"]);
                    });
                });
            });
        ');

        $this->assertArrayHasKey('GET /list/countries', $routes);
        $this->assertFalse($routes['GET /list/countries']->authorization->hasAuth);
        $this->assertArrayHasKey('PUT /auth/me/profile', $routes);
        $this->assertTrue($routes['PUT /auth/me/profile']->authorization->hasAuth);
        $this->assertContains('throttle:10,1', $routes['PUT /auth/me/profile']->authorization->middleware);
    }

    public function testArrowFunctionGroup(): void
    {
        $routes = $this->discoverByRoute('<?php
            Route::middleware("auth")->group(fn () => Route::delete("/sessions", [SessionController::class, "destroy"]));
        ');

        $this->assertArrayHasKey('DELETE /sessions', $routes);
        $this->assertTrue($routes['DELETE /sessions']->authorization->hasAuth);
    }

    public function testRouteWithTrailingNameIsDiscovered(): void
    {
        $routes = $this->discoverByRoute('<?php
            Route::post("/reset-password", [AuthController::class, "resetPassword"])->name("password.reset");
        ');

        $this->assertArrayHasKey('POST /reset-password', $routes);
        $this->assertSame('resetPassword', $routes['POST /reset-password']->actionName);
    }

    public function testTrailingMiddlewareGrantsAuth(): void
    {
        $routes = $this->discoverByRoute('<?php
            Route::get("/tokens", [TokenController::class, "index"])
                ->name("tokens.index")
                ->middleware(["auth:api", "user.admin"]);
        ');

        $this->assertArrayHasKey('GET /tokens', $routes);
        $this->assertTrue($routes['GET /tokens']->authorization->hasAuth);
        $this->assertContains('user.admin', $routes['GET /tokens']->authorization->middleware);
    }

    public function testTrailingCanAddsPolicy(): void
    {
        $routes = $this->discoverByRoute('<?php
            Route::put("/posts/{post}", [PostController::class, "update"])->can("update", "post");
        ');

        $this->assertTrue($routes['PUT /posts/{post}']->authorization->hasAuth);
        $this->assertContains('update', $routes['PUT /posts/{post}']->authorization->policies);
    }

    public function testWithoutMiddlewareRemovesGroupAuth(): void
    {
        $routes = $this->discoverByRoute('<?php
            Route::middleware("auth:sanctum")->group(function () {
                Route::get("/me", [MeController::class, "show"]);
                Route::post("/webhook", [HookController::class, "handle"])->withoutMiddleware("auth");
            });
        ');

        $this->assertTrue($routes['GET /me']->authorization->hasAuth);
        $this->assertFalse($routes['POST /webhook']->authorization->hasAuth);
    }

    public function testMatchRouteUsesSecondArgumentAsPath(): void
    {
        $routes = $this->discoverByRoute('<?php
            Route::match(["get", "post"], "/login/{provider}/callback", [AuthController::class, "callback"]);
        ');

        $this->assertArrayHasKey('GET, POST /login/{provider}/callback', $routes);
        $this->assertSame('callback', $routes['GET, POST /login/{provider}/callback']->actionName);
    }

    public function testInvokableControllerAction(): void
    {
        $routes = $this->discoverByRoute('<?php
            Route::put("/profile", ProfileSyncController::class);
        ');

        $this->assertSame('ProfileSyncController', $routes['PUT /profile']->controllerName);
        $this->assertSame('__invoke', $routes['PUT /profile']->actionName);
    }

    public function testControllerGroupResolvesStringActions(): void
    {
        $routes = $this->discoverByRoute('<?php
            Route::controller(OrderController::class)->prefix("orders")->group(function () {
                Route::get("/{id}", "show");
                Route::post("/", "store");
            });
        ');

        $this->assertSame('OrderController', $routes['GET /orders/{id}']->controllerName);
        $this->assertSame('show', $routes['GET /orders/{id}']->actionName);
        $this->assertArrayHasKey('POST /orders', $routes);
    }

    public function testRoutesInsideNamespaceAndConditionals(): void
    {
        $routes = $this->discoverByRoute('<?php
            namespace App\Routes;
            use Illuminate\Support\Facades\Route;
            if (app()->environment("local")) {
                Route::get("/debug", [DebugController::class, "index"]);
            } else {
                Route::get("/status", [StatusController::class, "index"]);
            }
        ');

        $this->assertArrayHasKey('GET /debug', $routes);
        $this->assertArrayHasKey('GET /status', $routes);
    }

    public function testDynamicGuardMiddlewareCountsAsAuth(): void
    {
        $routes = $this->discoverByRoute('<?php
            $guard = config("passport.guard");
            Route::prefix("oauth")->middleware(["web", $guard ? "auth:" . $guard : "auth"])->group(function () {
                Route::post("/clients", [ClientController::class, "store"]);
            });
        ');

        $this->assertArrayHasKey('POST /oauth/clients', $routes);
        $this->assertTrue($routes['POST /oauth/clients']->authorization->hasAuth);
    }

    public function testMiddlewareClassReferenceCountsAsAuth(): void
    {
        $routes = $this->discoverByRoute('<?php
            use Illuminate\Auth\Middleware\Authenticate;
            Route::middleware([Authenticate::class])->group(function () {
                Route::get("/orders", [OrderController::class, "index"]);
            });
        ');

        $this->assertTrue($routes['GET /orders']->authorization->hasAuth);
    }

    public function testApiResourceExpandsToRestEndpoints(): void
    {
        $routes = $this->discoverByRoute('<?php
            Route::middleware("auth:sanctum")->group(function () {
                Route::apiResource("photos", PhotoController::class);
            });
        ');

        $this->assertSame(
            ['DELETE /photos/{photo}', 'GET /photos', 'GET /photos/{photo}', 'POST /photos', 'PUT, PATCH /photos/{photo}'],
            $this->sortedKeys($routes),
        );
        foreach ($routes as $endpoint) {
            $this->assertTrue($endpoint->authorization->hasAuth);
            $this->assertSame('PhotoController', $endpoint->controllerName);
        }
    }

    public function testResourceHonoursOnlyExceptAndNesting(): void
    {
        $routes = $this->discoverByRoute('<?php
            Route::resource("categories.comments", CommentController::class)->only(["index", "store", "destroy"]);
            Route::resource("tags", TagController::class, ["except" => ["create", "edit", "show"]]);
        ');

        $this->assertSame(
            [
                'DELETE /categories/{category}/comments/{comment}',
                'DELETE /tags/{tag}',
                'GET /categories/{category}/comments',
                'GET /tags',
                'POST /categories/{category}/comments',
                'POST /tags',
                'PUT, PATCH /tags/{tag}',
            ],
            $this->sortedKeys($routes),
        );
    }

    public function testRequestGetCallsAreNotRoutes(): void
    {
        $code = '<?php
            class AuthController extends Controller {
                public function login(Request $request) {
                    $email = $request->get("email");
                    $this->router->get("/fake", fn () => null);
                    return collect($items)->get("phone_number");
                }
            }
        ';

        $this->assertSame([], $this->discoverByRoute($code));
    }

    public function testGroupLoadingAnotherFileIsNotARoute(): void
    {
        $routes = $this->discoverByRoute('<?php
            Route::prefix("api/v1")->middleware("api")->group(base_path("routes/api-v1.php"));
        ');

        $this->assertSame([], $routes);
    }

    /**
     * @param array<string, mixed> $routes
     * @return string[]
     */
    private function sortedKeys(array $routes): array
    {
        $keys = array_keys($routes);
        sort($keys);
        return $keys;
    }
}
