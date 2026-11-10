<?php

declare(strict_types=1);

namespace ApiPosture\Core\Discovery;

use ApiPosture\Core\Model\AuthorizationInfo;
use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\EndpointType;
use ApiPosture\Core\Model\Enums\HttpMethod;
use ApiPosture\Core\Model\SourceLocation;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;

final class LaravelEndpointDiscoverer implements EndpointDiscovererInterface
{
    private const ROUTE_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'any', 'match'];

    private const RESOURCE_METHODS = ['resource', 'apiresource', 'resources', 'apiresources'];

    private const AUTH_MIDDLEWARE = [
        'auth', 'auth:api', 'auth:sanctum', 'auth:web',
        'auth.basic', 'verified',
    ];

    private const ANONYMOUS_MIDDLEWARE = ['guest'];

    /**
     * Framework middleware referenced by class (Authenticate::class) mapped to their alias.
     */
    private const MIDDLEWARE_CLASS_ALIASES = [
        'authenticate' => 'auth',
        'authenticatewithbasicauth' => 'auth.basic',
        'ensureemailisverified' => 'verified',
        'redirectifauthenticated' => 'guest',
        'ensurefrontendrequestsarestateful' => 'auth:sanctum',
    ];

    public function supports(array $ast, string $filePath): bool
    {
        $finder = new NodeFinder();

        // Check for Route:: static calls
        $routeCalls = $finder->find($ast, function (Node $node) {
            return $this->isRouteStaticCall($node);
        });

        if (count($routeCalls) > 0) {
            return true;
        }

        // Check for Laravel controller patterns (extends Controller, uses middleware)
        $classes = $finder->findInstanceOf($ast, Stmt\Class_::class);
        foreach ($classes as $class) {
            if ($this->isLaravelController($class)) {
                return true;
            }
        }

        return false;
    }

    public function discover(array $ast, string $filePath): array
    {
        $endpoints = [];
        $finder = new NodeFinder();

        // Discover route file definitions (routes/web.php, routes/api.php style)
        $endpoints = array_merge($endpoints, $this->discoverRouteDefinitions($ast, $filePath, $finder));

        // Discover controller-based endpoints
        $endpoints = array_merge($endpoints, $this->discoverControllerEndpoints($ast, $filePath, $finder));

        return $endpoints;
    }

    /** @var array<int, array{path: string, prefix: string, middleware: string[]}> */
    private array $mounts = [];

    /**
     * Collect route files this file mounts, with the prefix and middleware they are mounted under.
     * Covers RouteServiceProvider/module providers (->group(base_path(...)), require inside a group,
     * $this->loadRoutesFrom(...)) and Laravel 11 bootstrap/app.php ->withRouting(api: ..., web: ...).
     *
     * @param Node[] $ast
     * @return array<int, array{path: string, prefix: string, middleware: string[]}>
     */
    public function collectRouteMounts(array $ast): array
    {
        $this->mounts = [];
        $emptyContext = ['middleware' => [], 'without' => [], 'prefixes' => [], 'controller' => null];
        $finder = new NodeFinder();

        // Top-level statements plus every function/method body (providers register routes in methods).
        $bodies = [$ast];
        foreach ($finder->find($ast, fn(Node $n) => $n instanceof Stmt\ClassMethod || $n instanceof Stmt\Function_) as $fn) {
            $bodies[] = $fn->stmts ?? [];
        }
        foreach ($bodies as $stmts) {
            $this->discoverRouteDefinitionsRecursive($stmts, '', $emptyContext);
        }

        // $this->loadRoutesFrom(__DIR__ . '/../routes/api.php')
        foreach ($finder->find($ast, fn(Node $n) => $n instanceof Expr\MethodCall
            && $n->name instanceof Node\Identifier
            && strtolower($n->name->toString()) === 'loadroutesfrom') as $call) {
            if (isset($this->callArgs($call)[0])) {
                $this->recordMount($this->callArgs($call)[0]->value, $emptyContext);
            }
        }

        // Laravel 11+: Application::configure()->withRouting(web: ..., api: ..., apiPrefix: 'api')
        foreach ($finder->find($ast, fn(Node $n) => $n instanceof Expr\MethodCall
            && $n->name instanceof Node\Identifier
            && strtolower($n->name->toString()) === 'withrouting') as $call) {
            $named = [];
            foreach ($this->callArgs($call) as $arg) {
                if ($arg->name !== null) {
                    $named[$arg->name->toString()] = $arg->value;
                }
            }
            $apiPrefix = isset($named['apiPrefix']) ? ($this->resolveStringValue($named['apiPrefix']) ?? 'api') : 'api';
            foreach (['web' => ['web', ''], 'api' => ['api', $apiPrefix]] as $key => [$group, $prefix]) {
                if (!isset($named[$key])) {
                    continue;
                }
                $paths = $named[$key] instanceof Expr\Array_
                    ? array_map(fn($i) => $i->value, array_filter($named[$key]->items))
                    : [$named[$key]];
                foreach ($paths as $pathExpr) {
                    $this->recordMount($pathExpr, [
                        'middleware' => [$group], 'without' => [],
                        'prefixes' => $prefix !== '' ? [$prefix] : [], 'controller' => null,
                    ]);
                }
            }
        }

        $mounts = $this->mounts;
        $this->mounts = [];

        $unique = [];
        foreach ($mounts as $mount) {
            $unique[md5(serialize($mount))] = $mount;
        }
        return array_values($unique);
    }

    /**
     * @param array{middleware: string[], without: string[], prefixes: string[], controller: ?string, namespaces?: string[]} $context
     */
    private function recordMount(Expr $pathExpr, array $context): void
    {
        $path = $this->resolveRouteFilePath($pathExpr);
        if ($path === null) {
            return;
        }
        $prefix = $this->buildFullPath($context['prefixes'], '');
        $this->mounts[] = [
            'path' => $path,
            'prefix' => $prefix === '/' ? '' : $prefix,
            'middleware' => $this->removeMiddleware($context['middleware'], $context['without']),
        ];
    }

    /**
     * Best-effort relative path of a route file from expressions such as base_path('routes/api.php'),
     * __DIR__ . '/../routes/api.php' or module_path($this->name, '/routes/api.php').
     * Returns a normalized suffix like 'routes/api.php', or null when not statically resolvable.
     */
    private function resolveRouteFilePath(Expr $expr): ?string
    {
        if ($expr instanceof Expr\Closure || $expr instanceof Expr\ArrowFunction || $expr instanceof Expr\Array_) {
            return null;
        }
        $strings = $expr instanceof Node\Scalar\String_
            ? [$expr]
            : (new NodeFinder())->findInstanceOf($expr, Node\Scalar\String_::class);
        $candidate = null;
        foreach ($strings as $string) {
            if (str_ends_with(strtolower($string->value), '.php')) {
                $candidate = $string->value;
            }
        }
        if ($candidate === null) {
            return null;
        }
        $segments = [];
        foreach (explode('/', str_replace('\\', '/', $candidate)) as $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..') {
                continue;
            }
            $segments[] = $segment;
        }
        return $segments === [] ? null : implode('/', $segments);
    }

    private function discoverRouteDefinitions(array $ast, string $filePath, NodeFinder $finder): array
    {
        return $this->discoverRouteDefinitionsRecursive($ast, $filePath, [
            'middleware' => [],
            'without' => [],
            'prefixes' => [],
            'controller' => null,
        ]);
    }

    /**
     * Recursively walk statements to discover routes, tracking group context
     * (middleware, excluded middleware, prefixes, group controller).
     *
     * @param Node[] $nodes
     * @param array{middleware: string[], without: string[], prefixes: string[], controller: ?string, namespaces?: string[]} $context
     * @return Endpoint[]
     */
    private function discoverRouteDefinitionsRecursive(array $nodes, string $filePath, array $context): array
    {
        $endpoints = [];

        foreach ($nodes as $node) {
            // Routes are often registered inside namespaces, conditionals, loops or try blocks.
            $nested = $this->nestedStatementLists($node);
            if ($nested !== null) {
                foreach ($nested as $stmts) {
                    $endpoints = array_merge($endpoints, $this->discoverRouteDefinitionsRecursive($stmts, $filePath, $context));
                }
                continue;
            }

            $expr = match (true) {
                $node instanceof Stmt\Expression => $node->expr,
                $node instanceof Stmt\Return_ => $node->expr,
                default => $node,
            };
            if (!$expr instanceof Expr) {
                continue;
            }

            // require base_path('routes/x.php') inside a group mounts that file under the group context.
            if ($expr instanceof Expr\Include_) {
                $this->recordMount($expr->expr, $context);
                continue;
            }

            // Group call: Route::group([...], fn), Route::middleware(...)->prefix(...)->group(fn), ...
            $groupInfo = $this->extractGroupInfo($expr);
            if ($groupInfo !== null) {
                $childContext = $context;
                $childContext['middleware'] = array_merge($context['middleware'], $groupInfo['middleware']);
                $childContext['without'] = array_merge($context['without'], $groupInfo['without']);
                if ($groupInfo['prefix'] !== '') {
                    $childContext['prefixes'][] = $groupInfo['prefix'];
                }
                if ($groupInfo['controller'] !== null) {
                    $childContext['controller'] = $groupInfo['controller'];
                }
                if ($groupInfo['namespace'] !== null) {
                    // Nested group namespaces append; a leading backslash makes them absolute.
                    $childContext['namespaces'] = str_starts_with($groupInfo['namespace'], '\\')
                        ? [trim($groupInfo['namespace'], '\\')]
                        : array_merge($context['namespaces'] ?? [], [trim($groupInfo['namespace'], '\\')]);
                }
                if ($groupInfo['file'] !== null) {
                    // ->group(base_path('routes/api.php')): routes live in another file.
                    $this->recordMount($groupInfo['file'], $childContext);
                    continue;
                }
                $endpoints = array_merge(
                    $endpoints,
                    $this->discoverRouteDefinitionsRecursive($groupInfo['statements'], $filePath, $childContext)
                );
                continue;
            }

            // Route definition, possibly followed by a trailing chain: Route::post(...)->name(...)->middleware(...)
            $route = $this->unwrapRouteCall($expr);
            if ($route === null) {
                continue;
            }

            $verb = strtolower($route['call']->name->toString());
            if (in_array($verb, self::RESOURCE_METHODS, true)) {
                $endpoints = array_merge(
                    $endpoints,
                    $this->parseResourceCall($route['call'], $route['trailing'], $filePath, $context)
                );
                continue;
            }

            $endpoint = $this->parseRouteCallWithContext($route['call'], $route['trailing'], $filePath, $context);
            if ($endpoint !== null) {
                $endpoints[] = $endpoint;
            }
        }

        return $endpoints;
    }

    /**
     * Statement lists nested inside a non-expression statement, or null for leaf statements.
     * Function and class bodies are deliberately not entered.
     *
     * @return array<Node[]>|null
     */
    private function nestedStatementLists(Node $node): ?array
    {
        return match (true) {
            $node instanceof Stmt\Namespace_,
            $node instanceof Stmt\Block,
            $node instanceof Stmt\Declare_,
            $node instanceof Stmt\Foreach_,
            $node instanceof Stmt\For_,
            $node instanceof Stmt\While_,
            $node instanceof Stmt\Do_ => [$node->stmts ?? []],
            $node instanceof Stmt\If_ => array_merge(
                [$node->stmts],
                array_map(fn(Stmt\ElseIf_ $e) => $e->stmts, $node->elseifs),
                $node->else !== null ? [$node->else->stmts] : [],
            ),
            $node instanceof Stmt\TryCatch => array_merge(
                [$node->stmts],
                array_map(fn(Stmt\Catch_ $c) => $c->stmts, $node->catches),
                $node->finally !== null ? [$node->finally->stmts] : [],
            ),
            $node instanceof Stmt\Switch_ => array_map(fn(Stmt\Case_ $c) => $c->stmts, $node->cases),
            default => null,
        };
    }

    /**
     * Find the route-registering call inside an expression, peeling off any trailing chain.
     *
     * Route::get('/x', ...)->name('x')->middleware('auth') yields call = Route::get(...)
     * and trailing = [->middleware('auth'), ->name('x')].
     *
     * @return array{call: Expr\StaticCall|Expr\MethodCall, trailing: Expr\MethodCall[]}|null
     */
    private function unwrapRouteCall(Expr $expr): ?array
    {
        $trailing = [];
        $current = $expr;

        while (true) {
            if ($this->isRouteMethodCall($current)) {
                /** @var Expr\StaticCall|Expr\MethodCall $current */
                return ['call' => $current, 'trailing' => $trailing];
            }
            if (!$current instanceof Expr\MethodCall) {
                return null;
            }
            $trailing[] = $current;
            $current = $current->var;
        }
    }

    /**
     * Extract group info (middleware, prefix, controller, closure statements) from a group call.
     *
     * @return array{middleware: string[], without: string[], prefix: string, controller: ?string, namespace: ?string, statements: Node[], file: ?Expr}|null
     */
    private function extractGroupInfo(Node $node): ?array
    {
        if (!$node instanceof Expr\MethodCall && !$node instanceof Expr\StaticCall) {
            return null;
        }

        if (!$node->name instanceof Node\Identifier || strtolower($node->name->toString()) !== 'group') {
            return null;
        }

        // Static form must be called on the Route facade: Route::group([...], fn)
        if ($node instanceof Expr\StaticCall && !$this->isRouteStaticCall($node)) {
            return null;
        }

        $middleware = [];
        $without = [];
        $prefixes = [];
        $controller = null;
        $namespace = null;
        $closureStmts = null;
        $fileExpr = null;

        foreach ($this->callArgs($node) as $arg) {
            $value = $arg->value;
            if ($value instanceof Expr\Closure) {
                $closureStmts = $value->stmts;
            } elseif ($value instanceof Expr\ArrowFunction) {
                $closureStmts = [new Stmt\Expression($value->expr)];
            } elseif ($this->resolveRouteFilePath($value) !== null) {
                $fileExpr = $value;
            } elseif ($value instanceof Expr\Array_) {
                // Route::group(['prefix' => '...', 'middleware' => ..., 'controller' => ...], fn)
                foreach ($value->items as $item) {
                    $key = $item?->key instanceof Node\Scalar\String_ ? $item->key->value : null;
                    if ($key === 'prefix') {
                        $p = $this->resolveStringValue($item->value);
                        if ($p !== null) {
                            $prefixes[] = $p;
                        }
                    } elseif ($key === 'middleware') {
                        $middleware = array_merge($middleware, $this->resolveMiddlewareValues($item->value));
                    } elseif ($key === 'excluded_middleware' || $key === 'withoutMiddleware') {
                        $without = array_merge($without, $this->resolveMiddlewareValues($item->value));
                    } elseif ($key === 'controller' && $item->value instanceof Expr\ClassConstFetch) {
                        $controller = $this->resolveClassName($item->value);
                    } elseif ($key === 'namespace') {
                        $namespace = $this->resolveStringValue($item->value) ?? $namespace;
                    }
                }
            }
        }

        // A group must either have a closure body or load a route file.
        if ($closureStmts === null && $fileExpr === null) {
            return null;
        }

        // Walk the registrar chain: Route::middleware([...])->prefix('/api')->controller(X::class)->group(...)
        $current = $node instanceof Expr\MethodCall ? $node->var : null;
        while ($current instanceof Expr\MethodCall || $current instanceof Expr\StaticCall) {
            if ($current->name instanceof Node\Identifier) {
                $callName = strtolower($current->name->toString());
                $args = $this->callArgs($current);
                if ($callName === 'middleware') {
                    $middleware = array_merge($middleware, $this->extractChainMiddlewareArgs($current));
                } elseif ($callName === 'withoutmiddleware') {
                    $without = array_merge($without, $this->extractChainMiddlewareArgs($current));
                } elseif ($callName === 'can' && count($args) > 0) {
                    $ability = $this->resolveStringValue($args[0]->value);
                    $middleware[] = 'can:' . ($ability ?? '*');
                } elseif ($callName === 'prefix' && count($args) > 0) {
                    $p = $this->resolveStringValue($args[0]->value);
                    if ($p !== null) {
                        // Chain is walked outermost-first, so earlier prefixes go in front.
                        array_unshift($prefixes, $p);
                    }
                } elseif ($callName === 'controller' && count($args) > 0 && $args[0]->value instanceof Expr\ClassConstFetch) {
                    $controller = $this->resolveClassName($args[0]->value);
                } elseif ($callName === 'namespace' && count($args) > 0) {
                    $namespace = $this->resolveStringValue($args[0]->value) ?? $namespace;
                }
            }

            $current = $current instanceof Expr\MethodCall ? $current->var : null;
        }

        $prefix = '';
        foreach ($prefixes as $p) {
            $prefix = $this->joinPath($prefix, $p);
        }

        return [
            'middleware' => $middleware,
            'without' => $without,
            'prefix' => $prefix === '/' ? '' : $prefix,
            'controller' => $controller,
            'namespace' => $namespace !== null && trim($namespace, '\\') !== '' ? $namespace : null,
            'statements' => $closureStmts ?? [],
            'file' => $fileExpr,
        ];
    }

    /**
     * Parse a route call with accumulated context from parent groups.
     *
     * @param Expr\MethodCall[] $trailing
     * @param array{middleware: string[], without: string[], prefixes: string[], controller: ?string, namespaces?: string[]} $context
     */
    private function parseRouteCallWithContext(Node $node, array $trailing, string $filePath, array $context): ?Endpoint
    {
        if (!$node instanceof Expr\StaticCall && !$node instanceof Expr\MethodCall) {
            return null;
        }

        $httpMethod = $this->getHttpMethodFromCall($node);
        if ($httpMethod === null) {
            return null;
        }

        // Route::match(['GET', 'POST'], '/path', $action) shifts path/action one position right.
        $isMatch = $node->name instanceof Node\Identifier && strtolower($node->name->toString()) === 'match';
        $pathIndex = $isMatch ? 1 : 0;

        $args = $this->callArgs($node);
        if (count($args) <= $pathIndex) {
            return null;
        }

        $path = $this->resolveStringValue($args[$pathIndex]->value);
        if ($path === null) {
            return null;
        }

        $fullPath = $this->buildFullPath($context['prefixes'], $path);

        // Resolve controller and action
        $controllerName = null;
        $actionName = null;
        if (isset($args[$pathIndex + 1])) {
            [$controllerName, $actionName] = $this->resolveControllerAction($args[$pathIndex + 1]->value, $context['controller']);
            // 'UserController@update' is relative to the enclosing group namespaces.
            if ($controllerName !== null && ($context['namespaces'] ?? []) !== []
                && !str_starts_with($controllerName, '\\') && $this->isStringControllerAction($args[$pathIndex + 1]->value)) {
                $controllerName = implode('\\', $context['namespaces']) . '\\' . $controllerName;
            }
        }

        // Middleware: group context + registrar chain before the verb + action array + trailing chain.
        $allMiddleware = array_merge(
            $context['middleware'],
            $this->getChainMiddleware($node),
            isset($args[$pathIndex + 1]) ? $this->getActionArrayMiddleware($args[$pathIndex + 1]->value) : [],
            $this->getTrailingMiddleware($trailing),
        );
        $allMiddleware = $this->removeMiddleware(
            $allMiddleware,
            array_merge($context['without'], $this->getTrailingWithoutMiddleware($trailing)),
        );

        $authInfo = $this->resolveAuthFromMiddleware($allMiddleware);
        if (isset($args[$pathIndex + 1])) {
            $authInfo = $this->withClosureAuth($authInfo, $args[$pathIndex + 1]->value);
        }

        return new Endpoint(
            route: $fullPath,
            methods: $httpMethod,
            type: EndpointType::Route,
            location: new SourceLocation($filePath, $node->getStartLine()),
            authorization: $authInfo,
            controllerName: $controllerName,
            actionName: $actionName,
        );
    }

    /**
     * Expand Route::resource / apiResource / resources / apiResources into their RESTful endpoints.
     *
     * @param Expr\MethodCall[] $trailing
     * @param array{middleware: string[], without: string[], prefixes: string[], controller: ?string, namespaces?: string[]} $context
     * @return Endpoint[]
     */
    private function parseResourceCall(Expr\StaticCall|Expr\MethodCall $call, array $trailing, string $filePath, array $context): array
    {
        $verb = strtolower($call->name->toString());
        $isApi = str_starts_with($verb, 'api');
        $args = $this->callArgs($call);
        if (count($args) < 1) {
            return [];
        }

        // Collect [name => controller] pairs.
        $resources = [];
        if ($verb === 'resources' || $verb === 'apiresources') {
            if (!$args[0]->value instanceof Expr\Array_) {
                return [];
            }
            foreach ($args[0]->value->items as $item) {
                $name = $item?->key !== null ? $this->resolveStringValue($item->key) : null;
                if ($name !== null) {
                    $resources[$name] = $item->value instanceof Expr\ClassConstFetch ? $this->resolveClassName($item->value) : null;
                }
            }
        } else {
            $name = $this->resolveStringValue($args[0]->value);
            if ($name === null) {
                return [];
            }
            $resources[$name] = isset($args[1]) && $args[1]->value instanceof Expr\ClassConstFetch
                ? $this->resolveClassName($args[1]->value)
                : null;
        }

        $actions = $isApi
            ? ['index', 'store', 'show', 'update', 'destroy']
            : ['index', 'create', 'store', 'show', 'edit', 'update', 'destroy'];

        // only/except from an options array (3rd arg) or a trailing ->only()/->except() chain.
        $only = null;
        $except = [];
        $optionsArg = $args[2]->value ?? null;
        if ($optionsArg instanceof Expr\Array_) {
            foreach ($optionsArg->items as $item) {
                $key = $item?->key instanceof Node\Scalar\String_ ? $item->key->value : null;
                if ($key === 'only') {
                    $only = $this->resolveStringList($item->value);
                } elseif ($key === 'except') {
                    $except = array_merge($except, $this->resolveStringList($item->value));
                }
            }
        }
        foreach ($trailing as $t) {
            $tName = $t->name instanceof Node\Identifier ? strtolower($t->name->toString()) : '';
            $tArgs = $this->callArgs($t);
            if ($tName === 'only' && count($tArgs) > 0) {
                $only = $this->resolveStringList($tArgs[0]->value);
            } elseif ($tName === 'except' && count($tArgs) > 0) {
                $except = array_merge($except, $this->resolveStringList($tArgs[0]->value));
            }
        }
        if ($only !== null) {
            $actions = array_values(array_intersect($actions, $only));
        }
        $actions = array_values(array_diff($actions, $except));

        $allMiddleware = $this->removeMiddleware(
            array_merge($context['middleware'], $this->getChainMiddleware($call), $this->getTrailingMiddleware($trailing)),
            array_merge($context['without'], $this->getTrailingWithoutMiddleware($trailing)),
        );
        $authInfo = $this->resolveAuthFromMiddleware($allMiddleware);

        $endpoints = [];
        foreach ($resources as $name => $controller) {
            [$base, $param] = $this->resourceBasePath($name);
            $member = $base . '/{' . $param . '}';
            $map = [
                'index' => [$base, [HttpMethod::GET]],
                'create' => [$base . '/create', [HttpMethod::GET]],
                'store' => [$base, [HttpMethod::POST]],
                'show' => [$member, [HttpMethod::GET]],
                'edit' => [$member . '/edit', [HttpMethod::GET]],
                'update' => [$member, [HttpMethod::PUT, HttpMethod::PATCH]],
                'destroy' => [$member, [HttpMethod::DELETE]],
            ];
            foreach ($actions as $action) {
                [$path, $methods] = $map[$action];
                $endpoints[] = new Endpoint(
                    route: $this->buildFullPath($context['prefixes'], $path),
                    methods: $methods,
                    type: EndpointType::Route,
                    location: new SourceLocation($filePath, $call->getStartLine()),
                    authorization: $authInfo,
                    controllerName: $controller ?? $context['controller'],
                    actionName: $action,
                );
            }
        }

        return $endpoints;
    }

    /**
     * 'photos' => ['/photos', 'photo']; 'photos.comments' => ['/photos/{photo}/comments', 'comment'].
     *
     * @return array{string, string}
     */
    private function resourceBasePath(string $name): array
    {
        $segments = array_values(array_filter(explode('.', trim($name, '/')), fn($s) => $s !== ''));
        $path = '';
        $param = 'id';
        foreach ($segments as $i => $segment) {
            $param = str_replace('-', '_', $this->singularize(basename($segment)));
            $path .= '/' . $segment;
            if ($i < count($segments) - 1) {
                $path .= '/{' . $param . '}';
            }
        }
        return [$path === '' ? '/' : $path, $param];
    }

    private function singularize(string $word): string
    {
        $lower = strtolower($word);
        if (str_ends_with($lower, 'ies') && strlen($word) > 3) {
            return substr($word, 0, -3) . 'y';
        }
        foreach (['sses', 'shes', 'ches', 'xes', 'zes'] as $suffix) {
            if (str_ends_with($lower, $suffix)) {
                return substr($word, 0, -2);
            }
        }
        if (str_ends_with($lower, 's') && !str_ends_with($lower, 'ss') && strlen($word) > 1) {
            return substr($word, 0, -1);
        }
        return $word;
    }

    /**
     * @param string[] $prefixes
     */
    private function buildFullPath(array $prefixes, string $path): string
    {
        $prefix = '';
        foreach ($prefixes as $p) {
            $prefix = $this->joinPath($prefix, $p);
        }
        $fullPath = $this->joinPath($prefix, $path);
        return $fullPath === '' ? '/' : $fullPath;
    }

    private function joinPath(string $left, string $right): string
    {
        $left = rtrim($left, '/');
        $right = trim($right, '/');
        if ($right === '') {
            return $left === '' ? '/' : $left;
        }
        return $left . '/' . $right;
    }

    private function isStringControllerAction(Expr $action): bool
    {
        if ($action instanceof Node\Scalar\String_) {
            return true;
        }
        if (!$action instanceof Expr\Array_) {
            return false;
        }
        foreach ($action->items as $index => $item) {
            if ($item?->key instanceof Node\Scalar\String_ && $item->key->value === 'uses') {
                return $item->value instanceof Node\Scalar\String_;
            }
            if ($index === 0 && $item?->key === null) {
                return $item?->value instanceof Node\Scalar\String_;
            }
        }
        return false;
    }

    /**
     * Middleware declared inside a legacy action array: ['middleware' => 'auth', 'uses' => ...].
     *
     * @return string[]
     */
    private function getActionArrayMiddleware(Expr $action): array
    {
        if (!$action instanceof Expr\Array_) {
            return [];
        }
        foreach ($action->items as $item) {
            if ($item?->key instanceof Node\Scalar\String_ && $item->key->value === 'middleware') {
                return $this->resolveMiddlewareValues($item->value);
            }
        }
        return [];
    }

    /**
     * @param Expr\MethodCall[] $trailing
     * @return string[]
     */
    private function getTrailingMiddleware(array $trailing): array
    {
        $middleware = [];
        foreach ($trailing as $call) {
            if (!$call->name instanceof Node\Identifier) {
                continue;
            }
            $name = strtolower($call->name->toString());
            if ($name === 'middleware') {
                $middleware = array_merge($middleware, $this->extractChainMiddlewareArgs($call));
            } elseif ($name === 'can' && count($this->callArgs($call)) > 0) {
                // Route::put(...)->can('update', 'post') is sugar for ->middleware('can:update,post')
                $ability = $this->resolveStringValue($this->callArgs($call)[0]->value);
                $middleware[] = 'can:' . ($ability ?? '*');
            }
        }
        return $middleware;
    }

    /**
     * @param Expr\MethodCall[] $trailing
     * @return string[]
     */
    private function getTrailingWithoutMiddleware(array $trailing): array
    {
        $without = [];
        foreach ($trailing as $call) {
            if ($call->name instanceof Node\Identifier && strtolower($call->name->toString()) === 'withoutmiddleware') {
                $without = array_merge($without, $this->extractChainMiddlewareArgs($call));
            }
        }
        return $without;
    }

    /**
     * Remove excluded middleware. Excluding 'auth' also drops guarded variants such as 'auth:api'.
     *
     * @param string[] $middleware
     * @param string[] $without
     * @return string[]
     */
    private function removeMiddleware(array $middleware, array $without): array
    {
        if ($without === []) {
            return array_values(array_unique($middleware));
        }
        $without = array_map('strtolower', $without);
        $kept = array_filter($middleware, function (string $mw) use ($without) {
            $lower = strtolower($mw);
            foreach ($without as $w) {
                if ($lower === $w || str_starts_with($lower, $w . ':')) {
                    return false;
                }
            }
            return true;
        });
        return array_values(array_unique($kept));
    }

    private function discoverControllerEndpoints(array $ast, string $filePath, NodeFinder $finder): array
    {
        $endpoints = [];
        $classes = $finder->findInstanceOf($ast, Stmt\Class_::class);

        foreach ($classes as $class) {
            if (!$this->isLaravelController($class)) {
                continue;
            }

            $controllerMiddleware = $this->getControllerMiddleware($class);
            $className = $class->name?->toString() ?? 'Unknown';

            foreach ($class->getMethods() as $method) {
                if (!$method->isPublic() || $method->name->toString() === '__construct') {
                    continue;
                }

                // Check for route attributes (Laravel 11+)
                $routeInfo = $this->getRouteAttribute($method);
                if ($routeInfo !== null) {
                    $methodMiddleware = $this->getMethodMiddleware($method);
                    $allMiddleware = array_merge($controllerMiddleware, $methodMiddleware);
                    $authInfo = $this->resolveAuthFromMiddleware($allMiddleware, $controllerMiddleware);

                    $endpoints[] = new Endpoint(
                        route: $routeInfo['path'],
                        methods: $routeInfo['methods'],
                        type: EndpointType::Controller,
                        location: new SourceLocation($filePath, $method->getStartLine()),
                        authorization: $authInfo,
                        controllerName: $className,
                        actionName: $method->name->toString(),
                    );
                }
            }
        }

        return $endpoints;
    }

    private function isRouteStaticCall(Node $node): bool
    {
        if (!$node instanceof Expr\StaticCall) {
            return false;
        }

        if (!$node->class instanceof Node\Name) {
            return false;
        }

        $className = $node->class->toString();
        return $className === 'Route' || str_ends_with($className, '\\Route');
    }

    private function isRouteMethodCall(Node $node): bool
    {
        // Route::get(), Route::post(), etc.
        if ($node instanceof Expr\StaticCall) {
            if (!$node->class instanceof Node\Name) {
                return false;
            }
            $className = $node->class->toString();
            if ($className !== 'Route' && !str_ends_with($className, '\\Route')) {
                return false;
            }
            if ($node->name instanceof Node\Identifier) {
                return $this->isRouteVerb($node->name->toString());
            }
        }

        // Chained method calls like Route::middleware('auth')->get()
        if ($node instanceof Expr\MethodCall) {
            if ($node->name instanceof Node\Identifier) {
                if ($this->isRouteVerb($node->name->toString())) {
                    return $this->isRouteChain($node->var);
                }
            }
        }

        return false;
    }

    private function isRouteVerb(string $name): bool
    {
        $lower = strtolower($name);
        return in_array($lower, self::ROUTE_METHODS, true) || in_array($lower, self::RESOURCE_METHODS, true);
    }

    private function isRouteChain(Expr $expr): bool
    {
        if ($expr instanceof Expr\StaticCall) {
            return $this->isRouteStaticCall($expr);
        }
        if ($expr instanceof Expr\MethodCall) {
            return $this->isRouteChain($expr->var);
        }
        return false;
    }

    /**
     * @return HttpMethod[]|null
     */
    private function getHttpMethodFromCall(Node $node): ?array
    {
        $name = null;
        if ($node instanceof Expr\StaticCall && $node->name instanceof Node\Identifier) {
            $name = strtolower($node->name->toString());
        } elseif ($node instanceof Expr\MethodCall && $node->name instanceof Node\Identifier) {
            $name = strtolower($node->name->toString());
        }

        if ($name === null) {
            return null;
        }

        return match ($name) {
            'get' => [HttpMethod::GET],
            'post' => [HttpMethod::POST],
            'put' => [HttpMethod::PUT],
            'delete' => [HttpMethod::DELETE],
            'patch' => [HttpMethod::PATCH],
            'any' => [HttpMethod::GET, HttpMethod::POST, HttpMethod::PUT, HttpMethod::DELETE, HttpMethod::PATCH],
            'match' => $this->resolveMatchMethods($node),
            default => null,
        };
    }

    /**
     * @return HttpMethod[]|null
     */
    private function resolveMatchMethods(Node $node): ?array
    {
        $args = $this->callArgs($node);
        if (count($args) < 1) {
            return null;
        }

        $firstArg = $args[0]->value;
        if (!$firstArg instanceof Expr\Array_) {
            return null;
        }

        $methods = [];
        foreach ($firstArg->items as $item) {
            if ($item?->value instanceof Node\Scalar\String_) {
                try {
                    $methods[] = HttpMethod::fromString($item->value->value);
                } catch (\InvalidArgumentException) {
                    // Skip unknown methods
                }
            }
        }

        return count($methods) > 0 ? $methods : null;
    }

    private function isLaravelController(Stmt\Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $parentName = $class->extends->toString();

        // Symfony controllers extend AbstractController — let SymfonyEndpointDiscoverer
        // handle them. Matching them here produces duplicate non-prefixed routes.
        if ($parentName === 'AbstractController'
            || str_ends_with($parentName, '\\AbstractController')) {
            return false;
        }

        return $parentName === 'Controller'
            || str_ends_with($parentName, '\\Controller')
            || str_contains($parentName, 'Controller');
    }

    /**
     * @return string[]
     */
    private function getControllerMiddleware(Stmt\Class_ $class): array
    {
        $middleware = [];
        $finder = new NodeFinder();

        // Look for $this->middleware() calls in constructor
        $constructors = array_filter(
            $class->getMethods(),
            fn($m) => $m->name->toString() === '__construct'
        );

        foreach ($constructors as $constructor) {
            $calls = $finder->find($constructor, function (Node $node) {
                return $node instanceof Expr\MethodCall
                    && $node->name instanceof Node\Identifier
                    && $node->name->toString() === 'middleware'
                    && $node->var instanceof Expr\Variable
                    && $node->var->name === 'this';
            });

            foreach ($calls as $call) {
                $middleware = array_merge($middleware, $this->extractMiddlewareNames($call));
            }
        }

        // Check for #[Middleware] attributes on the class
        foreach ($class->attrGroups as $attrGroup) {
            foreach ($attrGroup->attrs as $attr) {
                if ($this->isMiddlewareAttribute($attr)) {
                    $middleware = array_merge($middleware, $this->extractAttributeMiddleware($attr));
                }
            }
        }

        return $middleware;
    }

    /**
     * @return string[]
     */
    private function getMethodMiddleware(Stmt\ClassMethod $method): array
    {
        $middleware = [];
        foreach ($method->attrGroups as $attrGroup) {
            foreach ($attrGroup->attrs as $attr) {
                if ($this->isMiddlewareAttribute($attr)) {
                    $middleware = array_merge($middleware, $this->extractAttributeMiddleware($attr));
                }
            }
        }
        return $middleware;
    }

    /**
     * @return array{path: string, methods: HttpMethod[]}|null
     */
    private function getRouteAttribute(Stmt\ClassMethod $method): ?array
    {
        foreach ($method->attrGroups as $attrGroup) {
            foreach ($attrGroup->attrs as $attr) {
                $name = $attr->name->toString();
                if ($name === 'Route' || str_ends_with($name, '\\Route')) {
                    return $this->parseRouteAttribute($attr);
                }
            }
        }
        return null;
    }

    /**
     * @return array{path: string, methods: HttpMethod[]}|null
     */
    private function parseRouteAttribute(Node\Attribute $attr): ?array
    {
        $path = null;
        $methods = [HttpMethod::GET];

        foreach ($attr->args as $arg) {
            if ($arg->name === null || $arg->name->toString() === 'path' || $arg->name->toString() === 'uri') {
                if ($arg->value instanceof Node\Scalar\String_) {
                    $path = $arg->value->value;
                }
            } elseif ($arg->name?->toString() === 'methods') {
                if ($arg->value instanceof Expr\Array_) {
                    $methods = [];
                    foreach ($arg->value->items as $item) {
                        if ($item?->value instanceof Node\Scalar\String_) {
                            try {
                                $methods[] = HttpMethod::fromString($item->value->value);
                            } catch (\InvalidArgumentException) {
                            }
                        }
                    }
                }
            }
        }

        if ($path === null) {
            return null;
        }

        return ['path' => $path, 'methods' => $methods ?: [HttpMethod::GET]];
    }

    private function isMiddlewareAttribute(Node\Attribute $attr): bool
    {
        $name = $attr->name->toString();
        return $name === 'Middleware' || str_ends_with($name, '\\Middleware');
    }

    /**
     * @return string[]
     */
    private function extractAttributeMiddleware(Node\Attribute $attr): array
    {
        $middleware = [];
        foreach ($attr->args as $arg) {
            if ($arg->value instanceof Node\Scalar\String_) {
                $middleware[] = $arg->value->value;
            }
        }
        return $middleware;
    }

    /**
     * @return string[]
     */
    private function extractMiddlewareNames(Expr\MethodCall $call): array
    {
        $middleware = [];
        foreach ($this->callArgs($call) as $arg) {
            if ($arg->value instanceof Node\Scalar\String_) {
                $middleware[] = $arg->value->value;
            } elseif ($arg->value instanceof Expr\Array_) {
                foreach ($arg->value->items as $item) {
                    if ($item?->value instanceof Node\Scalar\String_) {
                        $middleware[] = $item->value->value;
                    }
                }
            }
        }
        return $middleware;
    }

    /**
     * @return string[]
     */
    private function getChainMiddleware(Node $node): array
    {
        $middleware = [];
        $current = $node;

        // Walk up the method chain looking for ->middleware() calls
        while ($current instanceof Expr\MethodCall || $current instanceof Expr\StaticCall) {
            if ($current instanceof Expr\MethodCall && $current->name instanceof Node\Identifier) {
                if ($current->name->toString() === 'middleware') {
                    $middleware = array_merge($middleware, $this->extractChainMiddlewareArgs($current));
                }
                $current = $current->var;
            } elseif ($current instanceof Expr\StaticCall) {
                if ($current->name instanceof Node\Identifier && $current->name->toString() === 'middleware') {
                    $middleware = array_merge($middleware, $this->extractChainMiddlewareArgs($current));
                }
                break;
            } else {
                break;
            }
        }

        // Also check if this call is part of a chain where middleware was applied earlier
        // e.g., Route::middleware(['auth'])->get(...)
        if ($node instanceof Expr\MethodCall && $node->var instanceof Expr\MethodCall) {
            $middleware = array_merge($middleware, $this->getChainMiddleware($node->var));
        }

        return array_unique($middleware);
    }

    /**
     * @return string[]
     */
    private function extractChainMiddlewareArgs(Node $call): array
    {
        $middleware = [];
        foreach ($this->callArgs($call) as $arg) {
            $middleware = array_merge($middleware, $this->resolveMiddlewareValues($arg->value));
        }
        return $middleware;
    }

    /**
     * Resolve a middleware expression to names. Handles literals, arrays, class references,
     * concatenation ('auth:' . $guard => 'auth:*') and conditionals (both branches).
     *
     * @return string[]
     */
    private function resolveMiddlewareValues(Node $value): array
    {
        if ($value instanceof Node\Scalar\String_) {
            return [$value->value];
        }

        if ($value instanceof Expr\Array_) {
            $names = [];
            foreach ($value->items as $item) {
                if ($item !== null) {
                    $names = array_merge($names, $this->resolveMiddlewareValues($item->value));
                }
            }
            return $names;
        }

        if ($value instanceof Expr\ClassConstFetch && $value->class instanceof Node\Name
            && $value->name instanceof Node\Identifier && strtolower($value->name->toString()) === 'class') {
            $short = strtolower($value->class->getLast());
            return [self::MIDDLEWARE_CLASS_ALIASES[$short] ?? $value->class->getLast()];
        }

        if ($value instanceof Expr\BinaryOp\Concat) {
            $left = $this->resolveStringValue($value->left);
            if ($left === null) {
                return [];
            }
            return [$left . ($this->resolveStringValue($value->right) ?? '*')];
        }

        // $cond ? 'auth:api' : 'auth' and $x ?? 'auth' — every branch is a middleware the route may run.
        if ($value instanceof Expr\Ternary) {
            $then = $value->if !== null ? $this->resolveMiddlewareValues($value->if) : $this->resolveMiddlewareValues($value->cond);
            return array_merge($then, $this->resolveMiddlewareValues($value->else));
        }
        if ($value instanceof Expr\BinaryOp\Coalesce) {
            return array_merge($this->resolveMiddlewareValues($value->left), $this->resolveMiddlewareValues($value->right));
        }

        return [];
    }

    /**
     * @return string[]
     */
    private function resolveStringList(Node $value): array
    {
        if ($value instanceof Expr\Array_) {
            $list = [];
            foreach ($value->items as $item) {
                $s = $item !== null ? $this->resolveStringValue($item->value) : null;
                if ($s !== null) {
                    $list[] = $s;
                }
            }
            return $list;
        }
        $s = $this->resolveStringValue($value);
        return $s !== null ? [$s] : [];
    }

    /**
     * @param string[] $allMiddleware
     * @param string[] $inheritedMiddleware
     */
    private function resolveAuthFromMiddleware(array $allMiddleware, array $inheritedMiddleware = []): AuthorizationInfo
    {
        $hasAuth = false;
        $hasAllowAnonymous = false;
        $roles = [];
        $policies = [];
        $inheritedFrom = null;

        foreach ($allMiddleware as $mw) {
            $mwLower = strtolower($mw);

            // Check auth middleware
            foreach (self::AUTH_MIDDLEWARE as $authMw) {
                if ($mwLower === strtolower($authMw) || str_starts_with($mwLower, strtolower($authMw) . ':')) {
                    $hasAuth = true;
                    break;
                }
            }

            // Laravel convention: custom guards are aliased auth.<something> (auth.session, auth.agent, auth.entity:pro)
            if (str_starts_with($mwLower, 'auth.')) {
                $hasAuth = true;
            }

            // Check anonymous middleware
            if (in_array($mwLower, array_map('strtolower', self::ANONYMOUS_MIDDLEWARE), true)) {
                $hasAllowAnonymous = true;
            }

            // Check role middleware: role:admin, role:admin|editor
            if (str_starts_with($mwLower, 'role:')) {
                $hasAuth = true;
                $roleStr = substr($mw, 5);
                $roles = array_merge($roles, explode('|', $roleStr));
            }

            // Check can/permission middleware: can:permission
            if (str_starts_with($mwLower, 'can:')) {
                $hasAuth = true;
                $policies[] = substr($mw, 4);
            }
        }

        // Determine if auth was inherited from controller
        if (!empty($inheritedMiddleware)) {
            foreach ($inheritedMiddleware as $mw) {
                foreach (self::AUTH_MIDDLEWARE as $authMw) {
                    if (strtolower($mw) === strtolower($authMw)) {
                        $inheritedFrom = 'controller';
                        break 2;
                    }
                }
            }
        }

        return new AuthorizationInfo(
            hasAuth: $hasAuth,
            hasAllowAnonymous: $hasAllowAnonymous,
            roles: array_unique($roles),
            policies: array_unique($policies),
            middleware: $allMiddleware,
            inheritedFrom: $inheritedFrom,
        );
    }

    /**
     * Protection that lives in a route closure itself:
     *  - a body that only rejects (abort(403), throw, return a 4xx response) reserves the URL: 'deny-all';
     *  - an inline 401/403 based on the caller's identity or a credential: 'inline-check'.
     */
    private function withClosureAuth(AuthorizationInfo $auth, Expr $action): AuthorizationInfo
    {
        $analyzer = new InlineAuthAnalyzer();
        if ($action instanceof Expr\ArrowFunction) {
            $policy = $analyzer->isRejection($action->expr) ? 'deny-all' : null;
        } elseif ($action instanceof Expr\Closure) {
            $policy = match (true) {
                $analyzer->deniesAll($action->stmts) => 'deny-all',
                $analyzer->enforcesAuth($action->stmts) => 'inline-check',
                default => null,
            };
        } else {
            return $auth;
        }
        if ($policy === null) {
            return $auth;
        }
        return new AuthorizationInfo(
            hasAuth: true,
            hasAllowAnonymous: $auth->hasAllowAnonymous,
            roles: $auth->roles,
            policies: array_values(array_unique([...$auth->policies, $policy])),
            middleware: $auth->middleware,
            inheritedFrom: $auth->inheritedFrom,
        );
    }

    /**
     * @return array{?string, ?string}
     */
    private function resolveControllerAction(Expr $expr, ?string $groupController = null): array
    {
        // Legacy action array: ['as' => 'name', 'middleware' => 'auth', 'uses' => 'Controller@method']
        if ($expr instanceof Expr\Array_) {
            $isKeyed = false;
            foreach ($expr->items as $item) {
                if ($item?->key instanceof Node\Scalar\String_) {
                    $isKeyed = true;
                    if ($item->key->value === 'uses') {
                        return $this->resolveControllerAction($item->value, $groupController);
                    }
                }
            }
            if ($isKeyed) {
                // ['as' => 'name', fn () => ...] — a named closure route with no controller.
                return [null, null];
            }
        }

        // Invokable controller: Route::put('/profile', ProfileSyncController::class)
        if ($expr instanceof Expr\ClassConstFetch && $expr->name instanceof Node\Identifier
            && strtolower($expr->name->toString()) === 'class') {
            return [$this->resolveClassName($expr), '__invoke'];
        }

        // Route::controller(X::class)->group(fn () => Route::get('/x', 'method'))
        if ($groupController !== null && $expr instanceof Node\Scalar\String_ && !str_contains($expr->value, '@')) {
            return [$groupController, $expr->value];
        }

        // [Controller::class, 'method']
        if ($expr instanceof Expr\Array_ && count($expr->items) >= 2) {
            $controller = null;
            $action = null;

            if ($expr->items[0]?->value instanceof Expr\ClassConstFetch) {
                $controller = $this->resolveClassName($expr->items[0]->value);
            } elseif ($expr->items[0]?->value instanceof Node\Scalar\String_) {
                $controller = $expr->items[0]->value->value;
            }

            if ($expr->items[1]?->value instanceof Node\Scalar\String_) {
                $action = $expr->items[1]->value->value;
            }

            return [$controller, $action];
        }

        // String 'Controller@method'
        if ($expr instanceof Node\Scalar\String_ && str_contains($expr->value, '@')) {
            [$controller, $action] = explode('@', $expr->value, 2);
            return [$controller, $action];
        }

        return [null, null];
    }

    private function resolveClassName(Expr\ClassConstFetch $node): ?string
    {
        if ($node->class instanceof Node\Name) {
            return $node->class->toString();
        }
        return null;
    }

    private function resolveStringValue(Node $node): ?string
    {
        if ($node instanceof Node\Scalar\String_) {
            return $node->value;
        }
        if ($node instanceof Expr\BinaryOp\Concat) {
            $left = $this->resolveStringValue($node->left);
            $right = $this->resolveStringValue($node->right);
            return $left !== null && $right !== null ? $left . $right : null;
        }
        return null;
    }

    /**
     * Call arguments, or none for first-class callables (foo(...)), where getArgs() is invalid.
     *
     * @return Node\Arg[]
     */
    private function callArgs(Expr\CallLike $call): array
    {
        return $call->isFirstClassCallable() ? [] : $call->getArgs();
    }
}
