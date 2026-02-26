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

    private const AUTH_MIDDLEWARE = [
        'auth', 'auth:api', 'auth:sanctum', 'auth:web',
        'auth.basic', 'verified',
    ];

    private const ANONYMOUS_MIDDLEWARE = ['guest'];

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

    private function discoverRouteDefinitions(array $ast, string $filePath, NodeFinder $finder): array
    {
        return $this->discoverRouteDefinitionsRecursive($ast, $filePath, [], []);
    }

    /**
     * Recursively walk statements to discover routes, tracking group middleware/prefix context.
     *
     * @param Node[] $nodes
     * @param string[] $contextMiddleware
     * @param string[] $contextPrefixes
     * @return Endpoint[]
     */
    private function discoverRouteDefinitionsRecursive(array $nodes, string $filePath, array $contextMiddleware, array $contextPrefixes): array
    {
        $endpoints = [];

        foreach ($nodes as $node) {
            // Extract the expression from expression statements
            $expr = $node instanceof Stmt\Expression ? $node->expr : $node;

            // Check if this is a group call: Route::middleware([...])->group(closure) or Route::group([...], closure)
            $groupInfo = $this->extractGroupInfo($expr);
            if ($groupInfo !== null) {
                $mergedMiddleware = array_merge($contextMiddleware, $groupInfo['middleware']);
                $mergedPrefixes = $contextPrefixes;
                if (!empty($groupInfo['prefix'])) {
                    $mergedPrefixes[] = $groupInfo['prefix'];
                }
                $endpoints = array_merge(
                    $endpoints,
                    $this->discoverRouteDefinitionsRecursive($groupInfo['statements'], $filePath, $mergedMiddleware, $mergedPrefixes)
                );
                continue;
            }

            // Check if this is a route method call: Route::get(), Route::post(), etc.
            if ($this->isRouteMethodCall($expr)) {
                $endpoint = $this->parseRouteCallWithContext($expr, $filePath, $contextMiddleware, $contextPrefixes);
                if ($endpoint !== null) {
                    $endpoints[] = $endpoint;
                }
            }
        }

        return $endpoints;
    }

    /**
     * Extract group info (middleware, prefix, closure statements) from a group call.
     *
     * @return array{middleware: string[], prefix: string, statements: Stmt[]}|null
     */
    private function extractGroupInfo(Node $node): ?array
    {
        if (!$node instanceof Expr\MethodCall) {
            return null;
        }

        if (!$node->name instanceof Node\Identifier || $node->name->toString() !== 'group') {
            return null;
        }

        $middleware = [];
        $prefix = '';
        $closureStmts = [];

        // Extract closure from group args
        foreach ($node->getArgs() as $arg) {
            if ($arg->value instanceof Expr\Closure) {
                $closureStmts = $arg->value->stmts ?? [];
            } elseif ($arg->value instanceof Expr\ArrowFunction) {
                // Arrow functions don't have stmts
                continue;
            } elseif ($arg->value instanceof Expr\Array_) {
                // Route::group(['prefix' => '...', 'middleware' => ...], closure)
                foreach ($arg->value->items as $item) {
                    if ($item?->key instanceof Node\Scalar\String_) {
                        if ($item->key->value === 'prefix') {
                            $p = $this->resolveStringValue($item->value);
                            if ($p !== null) {
                                $prefix = $p;
                            }
                        } elseif ($item->key->value === 'middleware') {
                            if ($item->value instanceof Node\Scalar\String_) {
                                $middleware[] = $item->value->value;
                            } elseif ($item->value instanceof Expr\Array_) {
                                foreach ($item->value->items as $mwItem) {
                                    if ($mwItem?->value instanceof Node\Scalar\String_) {
                                        $middleware[] = $mwItem->value->value;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Walk the chain (var) to find middleware/prefix calls:
        // Route::middleware(['auth'])->prefix('/api')->group(...)
        $current = $node->var;
        while ($current instanceof Expr\MethodCall || $current instanceof Expr\StaticCall) {
            $callName = null;
            if ($current instanceof Expr\MethodCall && $current->name instanceof Node\Identifier) {
                $callName = $current->name->toString();
            } elseif ($current instanceof Expr\StaticCall && $current->name instanceof Node\Identifier) {
                $callName = $current->name->toString();
            }

            if ($callName === 'middleware') {
                $middleware = array_merge($middleware, $this->extractChainMiddlewareArgs($current));
            } elseif ($callName === 'prefix' && count($current->getArgs()) > 0) {
                $p = $this->resolveStringValue($current->getArgs()[0]->value);
                if ($p !== null) {
                    $prefix = $p;
                }
            }

            $current = $current instanceof Expr\MethodCall ? $current->var : null;
            if ($current === null) {
                break;
            }
        }

        if (empty($closureStmts)) {
            return null;
        }

        return [
            'middleware' => $middleware,
            'prefix' => $prefix,
            'statements' => $closureStmts,
        ];
    }

    /**
     * Parse a route call with accumulated context from parent groups.
     */
    private function parseRouteCallWithContext(Node $node, string $filePath, array $contextMiddleware, array $contextPrefixes): ?Endpoint
    {
        if (!$node instanceof Expr\StaticCall && !$node instanceof Expr\MethodCall) {
            return null;
        }

        $httpMethod = $this->getHttpMethodFromCall($node);
        if ($httpMethod === null) {
            return null;
        }

        $args = $node->getArgs();
        if (count($args) < 1) {
            return null;
        }

        $path = $this->resolveStringValue($args[0]->value);
        if ($path === null) {
            return null;
        }

        // Build full path from context prefixes
        $prefix = '';
        foreach ($contextPrefixes as $p) {
            $prefix = rtrim($prefix, '/') . '/' . ltrim($p, '/');
        }
        $fullPath = rtrim($prefix, '/') . '/' . ltrim($path, '/');
        if ($fullPath === '') {
            $fullPath = '/';
        }

        // Resolve controller and action
        $controllerName = null;
        $actionName = null;
        if (count($args) >= 2) {
            [$controllerName, $actionName] = $this->resolveControllerAction($args[1]->value);
        }

        // Merge chain middleware with context middleware
        $chainMiddleware = $this->getChainMiddleware($node);
        $allMiddleware = array_merge($contextMiddleware, $chainMiddleware);

        $authInfo = $this->resolveAuthFromMiddleware($allMiddleware);

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
                return in_array(strtolower($node->name->toString()), self::ROUTE_METHODS, true);
            }
        }

        // Chained method calls like Route::middleware('auth')->get()
        if ($node instanceof Expr\MethodCall) {
            if ($node->name instanceof Node\Identifier) {
                $methodName = strtolower($node->name->toString());
                if (in_array($methodName, self::ROUTE_METHODS, true)) {
                    return $this->isRouteChain($node->var);
                }
            }
        }

        return false;
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
        $args = $node->getArgs();
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
        foreach ($call->getArgs() as $arg) {
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
        foreach ($call->getArgs() as $arg) {
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
     * @return array{?string, ?string}
     */
    private function resolveControllerAction(Expr $expr): array
    {
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
        return null;
    }
}
