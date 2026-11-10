<?php

declare(strict_types=1);

namespace ApiPosture\Core\Discovery;

use ApiPosture\Core\Model\AuthorizationInfo;
use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\SourceLocation;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;

/**
 * Project-wide Laravel knowledge that a single route file cannot provide:
 *
 *  - where each route file is mounted (prefix + middleware from RouteServiceProvider,
 *    module providers or bootstrap/app.php withRouting()),
 *  - what middleware aliases and groups resolve to (Http\Kernel, bootstrap/app.php),
 *  - which middleware classes actually enforce authentication, judged by their handle() body.
 *
 * Built incrementally while files are parsed, then applied to the discovered endpoints.
 */
final class LaravelProjectContext
{
    /** Framework/package middleware that always require an authenticated caller (lower-case short names). */
    private const KNOWN_AUTH_CLASSES = [
        'authenticate', 'authenticatewithbasicauth', 'authenticatesession', 'ensureemailisverified',
        'checkclientcredentials', 'checkclientcredentialsforanyscope', 'checkscopes', 'checkforanyscope',
        'checkabilities', 'checkforanyability', 'checktoken', 'checktokenforanyscope',
        'authorize', 'requirepassword',
    ];

    /** Laravel's default groups, used when the project does not declare its own. */
    private const DEFAULT_GROUPS = [
        'web' => ['EncryptCookies', 'AddQueuedCookiesToResponse', 'StartSession', 'ShareErrorsFromSession', 'VerifyCsrfToken', 'SubstituteBindings'],
        'api' => ['SubstituteBindings'],
    ];

    /** @var array<string, string> alias (lower) => class FQN or alias */
    private array $aliases = [];

    /** @var array<string, array<int, array{type: string, value: string}>> group (lower) => members */
    private array $groups = [];

    /** @var array<string, array{extends: ?string, auth: bool, delegates: string[]}> class FQN (lower) => middleware facts */
    private array $middlewareClasses = [];

    /** @var array<int, array{source: string, path: string, prefix: string, middleware: string[]}> */
    private array $mounts = [];

    /**
     * Controller-like classes: lower FQN => facts used to resolve route handlers.
     *
     * @var array<string, array{fqn: string, file: string, extends: ?string,
     *     middleware: array<int, array{name: string, only: ?string[], except: string[]}>,
     *     resourceAuthorized: bool,
     *     methods: array<string, array{line: int, abilities: string[], params: string[]}>}>
     */
    private array $classes = [];

    /**
     * Classes declaring authorize() (FormRequests): lower FQN => whether it can deny, and its parent.
     *
     * @var array<string, array{denies: bool, extends: ?string}>
     */
    private array $formRequests = [];

    /** @var array<string, string[]> lower short class name => lower FQNs */
    private array $shortIndex = [];

    /** @var array<string, array<string, string>> relative file => (lower alias => FQN) */
    private array $imports = [];

    /** @var array<string, bool>|null class FQN (lower) => is auth, resolved through inheritance */
    private ?array $authClassCache = null;

    private LaravelEndpointDiscoverer $routeDiscoverer;

    private InlineAuthAnalyzer $inlineAuth;

    public function __construct()
    {
        $this->routeDiscoverer = new LaravelEndpointDiscoverer();
        $this->inlineAuth = new InlineAuthAnalyzer();
    }

    /**
     * @param Node[] $ast
     */
    public function collect(array $ast, string $relativePath): void
    {
        $this->authClassCache = null;

        // Resolve names into attributes only, so the AST shared with discoverers is not rewritten.
        $traverser = new NodeTraverser();
        $traverser->addVisitor(new NameResolver(null, ['replaceNodes' => false]));
        $traverser->traverse($ast);

        $finder = new NodeFinder();

        $this->collectImports($ast, $relativePath);

        foreach ($finder->findInstanceOf($ast, Stmt\Class_::class) as $class) {
            $this->collectKernelProperties($class);
            $this->collectMiddlewareClass($class);
            $this->collectControllerClass($class, $relativePath);
        }

        foreach ($finder->findInstanceOf($ast, Expr\MethodCall::class) as $call) {
            $this->collectMiddlewareRegistration($call);
        }
        foreach ($finder->findInstanceOf($ast, Expr\StaticCall::class) as $call) {
            $this->collectMiddlewareRegistration($call);
        }

        foreach ($this->routeDiscoverer->collectRouteMounts($ast) as $mount) {
            $this->mounts[] = ['source' => $relativePath] + $mount;
        }
    }

    /**
     * Apply mounts, middleware groups and middleware-class auth analysis to discovered endpoints.
     *
     * @param Endpoint[] $endpoints
     * @return Endpoint[]
     */
    public function apply(array $endpoints, string $rootPath): array
    {
        $root = rtrim(str_replace('\\', '/', $rootPath), '/');
        $result = [];

        $relativePaths = [];
        foreach ($endpoints as $endpoint) {
            $relativePaths[$this->relativePath($endpoint->location->filePath, $root)] = true;
        }
        $mountsByTarget = $this->resolveMountTargets(array_keys($relativePaths));

        foreach ($endpoints as $endpoint) {
            $relative = $this->relativePath($endpoint->location->filePath, $root);
            $mounts = $this->effectiveMounts($relative, $mountsByTarget, []);

            $seen = [];
            foreach ($mounts as $mount) {
                $enriched = $this->enrich($endpoint, $mount, $relative, $root);
                $key = $enriched->methodsString() . ' ' . $enriched->route . ' ' . implode(',', $enriched->authorization->middleware);
                if (isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;
                $result[] = $enriched;
            }
        }

        return $result;
    }

    /**
     * Whether a middleware reference (alias, alias:params, group or class name) enforces authentication.
     */
    public function isAuthMiddleware(string $middleware, array $visiting = []): bool
    {
        $base = strtolower(trim(explode(':', $middleware, 2)[0]));
        if ($base === '' || isset($visiting[$base])) {
            return false;
        }
        $visiting[$base] = true;

        if (in_array($base, ['auth', 'auth.basic', 'verified', 'can', 'role', 'permission', 'abilities', 'ability', 'scopes', 'scope'], true)) {
            return true;
        }

        if (isset($this->aliases[$base])) {
            return $this->isAuthReference($this->aliases[$base], $visiting);
        }

        if (isset($this->groups[$base])) {
            foreach ($this->groups[$base] as $member) {
                if ($this->isAuthReference($member['value'], $visiting)) {
                    return true;
                }
            }
            return false;
        }

        if ($this->isAuthReference($middleware, $visiting)) {
            return true;
        }

        // Convention for custom guards when no alias map is available: auth.agent, auth.entity:pro
        return str_starts_with($base, 'auth.');
    }

    // -------------------------------------------------------------------------
    // Collection
    // -------------------------------------------------------------------------

    private function collectKernelProperties(Stmt\Class_ $class): void
    {
        foreach ($class->getProperties() as $property) {
            foreach ($property->props as $prop) {
                $name = $prop->name->toString();
                if (!$prop->default instanceof Expr\Array_) {
                    continue;
                }
                if ($name === 'routeMiddleware' || $name === 'middlewareAliases') {
                    $this->addAliases($prop->default);
                } elseif ($name === 'middlewareGroups') {
                    foreach ($prop->default->items as $item) {
                        $group = $item?->key !== null ? $this->stringValue($item->key) : null;
                        if ($group !== null && $item->value instanceof Expr\Array_) {
                            $this->groups[strtolower($group)] = $this->middlewareList($item->value);
                        }
                    }
                }
            }
        }
    }

    /**
     * bootstrap/app.php ->withMiddleware(fn (Middleware $middleware) => $middleware->alias([...])->group(...)),
     * Route::aliasMiddleware('x', X::class), $router->middlewareGroup('api', [...]).
     */
    private function collectMiddlewareRegistration(Expr\MethodCall|Expr\StaticCall $call): void
    {
        if (!$call->name instanceof Node\Identifier) {
            return;
        }
        $name = strtolower($call->name->toString());
        $args = $this->callArgs($call);

        // Only the Middleware configurator / router, never Route::group(...) route groups.
        $onMiddlewareConfigurator = $call instanceof Expr\MethodCall
            && $call->var instanceof Expr\Variable && is_string($call->var->name)
            && strtolower($call->var->name) === 'middleware';

        switch ($name) {
            case 'alias':
                if ($onMiddlewareConfigurator && isset($args[0]) && $args[0]->value instanceof Expr\Array_) {
                    $this->addAliases($args[0]->value);
                }
                break;
            case 'aliasmiddleware':
                if (count($args) >= 2) {
                    $alias = $this->stringValue($args[0]->value);
                    $target = $this->middlewareReference($args[1]->value);
                    if ($alias !== null && $target !== null) {
                        $this->aliases[strtolower($alias)] = $target['value'];
                    }
                }
                break;
            case 'group':
                if (!$onMiddlewareConfigurator) {
                    break;
                }
                // no break — $middleware->group('name', [...]) behaves like middlewareGroup()
            case 'middlewaregroup':
            case 'appendtogroup':
            case 'prependtogroup':
            case 'pushmiddlewaretogroup':
                if (count($args) >= 2) {
                    $group = $this->stringValue($args[0]->value);
                    if ($group === null) {
                        break;
                    }
                    $members = $args[1]->value instanceof Expr\Array_
                        ? $this->middlewareList($args[1]->value)
                        : array_filter([$this->middlewareReference($args[1]->value)]);
                    $key = strtolower($group);
                    $existing = ($name === 'group' || $name === 'middlewaregroup') ? [] : ($this->groups[$key] ?? []);
                    $this->groups[$key] = array_values(array_merge($existing, $members));
                }
                break;
            case 'api':
            case 'web':
                if ($onMiddlewareConfigurator) {
                    // $middleware->api(append: [...], prepend: [...]) extends Laravel's default group.
                    $members = $this->groups[$name] ?? array_map(
                        fn(string $c) => ['type' => 'class', 'value' => $c],
                        self::DEFAULT_GROUPS[$name],
                    );
                    foreach ($args as $arg) {
                        if ($arg->value instanceof Expr\Array_) {
                            $members = array_merge($members, $this->middlewareList($arg->value));
                        }
                    }
                    $this->groups[$name] = array_values($members);
                }
                break;
        }
    }

    private function collectMiddlewareClass(Stmt\Class_ $class): void
    {
        $handle = $class->getMethod('handle');
        $fqn = $this->classFqn($class);
        if ($fqn === null) {
            return;
        }

        $extends = $class->extends !== null ? $this->resolvedName($class->extends) : null;
        if ($handle === null && $extends === null) {
            return;
        }

        $this->middlewareClasses[strtolower($fqn)] = [
            'extends' => $extends,
            'auth' => $handle !== null && $this->inlineAuth->enforcesAuth($handle->stmts ?? []),
            'delegates' => $handle !== null ? $this->delegatedMiddleware($class, $handle) : [],
        ];
    }

    /**
     * Middleware that handle() hands the request to: $this->inner->handle($request, $next, ...)
     * or (new Inner())->handle(...). The property's class comes from a typed or promoted property.
     *
     * @return string[] class FQNs
     */
    private function delegatedMiddleware(Stmt\Class_ $class, Stmt\ClassMethod $handle): array
    {
        $propertyTypes = [];
        foreach ($class->getProperties() as $property) {
            if ($property->type instanceof Node\Name) {
                foreach ($property->props as $prop) {
                    $propertyTypes[strtolower($prop->name->toString())] = $this->resolvedName($property->type);
                }
            }
        }
        $constructor = $class->getMethod('__construct');
        foreach ($constructor?->params ?? [] as $param) {
            if ($param->flags !== 0 && $param->type instanceof Node\Name && $param->var instanceof Expr\Variable && is_string($param->var->name)) {
                $propertyTypes[strtolower($param->var->name)] = $this->resolvedName($param->type);
            }
        }

        $delegates = [];
        $finder = new NodeFinder();
        foreach ($finder->findInstanceOf($handle->stmts ?? [], Expr\MethodCall::class) as $call) {
            if (!$call->name instanceof Node\Identifier || strtolower($call->name->toString()) !== 'handle') {
                continue;
            }
            $target = $call->var;
            if ($target instanceof Expr\PropertyFetch && $target->var instanceof Expr\Variable && $target->var->name === 'this'
                && $target->name instanceof Node\Identifier && isset($propertyTypes[strtolower($target->name->toString())])) {
                $delegates[] = $propertyTypes[strtolower($target->name->toString())];
            } elseif ($target instanceof Expr\New_ && $target->class instanceof Node\Name) {
                $delegates[] = $this->resolvedName($target->class);
            }
        }
        return array_values(array_unique($delegates));
    }

    private function addAliases(Expr\Array_ $array): void
    {
        foreach ($array->items as $item) {
            $alias = $item?->key !== null ? $this->stringValue($item->key) : null;
            $target = $item !== null ? $this->middlewareReference($item->value) : null;
            if ($alias !== null && $target !== null) {
                $this->aliases[strtolower($alias)] = $target['value'];
            }
        }
    }

    /**
     * @return array<int, array{type: string, value: string}>
     */
    private function middlewareList(Expr\Array_ $array): array
    {
        $list = [];
        foreach ($array->items as $item) {
            $ref = $item !== null ? $this->middlewareReference($item->value) : null;
            if ($ref !== null) {
                $list[] = $ref;
            }
        }
        return $list;
    }

    /**
     * @return array{type: string, value: string}|null
     */
    private function middlewareReference(Node $value): ?array
    {
        if ($value instanceof Expr\ClassConstFetch && $value->class instanceof Node\Name
            && $value->name instanceof Node\Identifier && strtolower($value->name->toString()) === 'class') {
            return ['type' => 'class', 'value' => $this->resolvedName($value->class)];
        }
        $string = $this->stringValue($value);
        if ($string === null) {
            return null;
        }
        // 'App\Http\Middleware\Foo' written as a string is still a class reference.
        return str_contains($string, '\\')
            ? ['type' => 'class', 'value' => ltrim($string, '\\')]
            : ['type' => 'alias', 'value' => $string];
    }

    // -------------------------------------------------------------------------
    // Application
    // -------------------------------------------------------------------------

    /**
     * @param array{prefix: string, middleware: string[]} $mount
     */
    private function enrich(Endpoint $endpoint, array $mount, string $relative, string $root): Endpoint
    {
        $auth = $endpoint->authorization;

        // Controller-declared middleware (constructor / HasMiddleware) and gate checks in the action.
        $controller = $this->resolveController($endpoint->controllerName, $relative);
        $controllerMiddleware = [];
        $abilities = [];
        $handlerLocation = $endpoint->handlerLocation;
        if ($controller !== null) {
            $action = strtolower($endpoint->actionName ?? '__invoke');
            $controllerMiddleware = $this->controllerMiddlewareFor($controller, $action, []);
            $method = $this->findMethod($controller, $action, []);
            if ($method !== null) {
                $abilities = $method['abilities'];
                $handlerLocation ??= new SourceLocation($root . '/' . $method['file'], $method['line']);
                // A FormRequest whose authorize() can deny runs before the action.
                foreach ($method['params'] ?? [] as $paramClass) {
                    if ($this->formRequestDenies(strtolower($paramClass), [])) {
                        $abilities[] = $this->shortName($paramClass) . '::authorize';
                    }
                }
            }
            if ($this->resourceAuthorized($controller, [])) {
                $abilities[] = $action;
            }
        }

        $route = $endpoint->route;
        if ($mount['prefix'] !== '') {
            $route = '/' . trim(trim($mount['prefix'], '/') . '/' . trim($route, '/'), '/');
        }

        $declared = array_values(array_unique(array_merge($mount['middleware'], $auth->middleware, $controllerMiddleware)));
        $effective = $this->expandGroups($declared);

        $hasAuth = $auth->hasAuth || $abilities !== [];
        if (!$hasAuth) {
            foreach ($declared as $middleware) {
                if ($this->isAuthMiddleware($middleware)) {
                    $hasAuth = true;
                    break;
                }
            }
        }

        $hasAnonymous = $auth->hasAllowAnonymous || in_array('guest', array_map('strtolower', $declared), true);

        $policies = array_values(array_unique(array_merge($auth->policies, $abilities)));
        $roles = array_values(array_unique(array_merge($auth->roles, $this->rolesFromMiddleware($declared))));

        if ($route === $endpoint->route && $hasAuth === $auth->hasAuth && $policies === $auth->policies && $roles === $auth->roles
            && $hasAnonymous === $auth->hasAllowAnonymous && $effective === $auth->middleware
            && $handlerLocation === $endpoint->handlerLocation) {
            return $endpoint;
        }

        $inheritedFrom = $auth->inheritedFrom;
        if ($inheritedFrom === null && $hasAuth && !$auth->hasAuth) {
            $inheritedFrom = ($controllerMiddleware !== [] || $abilities !== []) && !$this->anyAuth(array_merge($mount['middleware'], $auth->middleware))
                ? 'controller'
                : 'route-group';
        }

        return new Endpoint(
            route: $route,
            methods: $endpoint->methods,
            type: $endpoint->type,
            location: $endpoint->location,
            authorization: new AuthorizationInfo(
                hasAuth: $hasAuth,
                hasAllowAnonymous: $hasAnonymous,
                roles: $roles,
                policies: $policies,
                middleware: $effective,
                inheritedFrom: $inheritedFrom,
            ),
            classification: $endpoint->classification,
            controllerName: $endpoint->controllerName,
            actionName: $endpoint->actionName,
            handlerLocation: $handlerLocation,
        );
    }

    /**
     * Declared middleware followed by the members of any middleware groups among them.
     *
     * @param string[] $declared
     * @return string[]
     */
    private function expandGroups(array $declared): array
    {
        $result = $declared;
        $queue = $declared;
        $visited = [];
        while ($queue !== []) {
            $name = strtolower((string) array_shift($queue));
            if (isset($visited[$name])) {
                continue;
            }
            $visited[$name] = true;
            $members = $this->groups[$name] ?? (isset(self::DEFAULT_GROUPS[$name])
                ? array_map(fn(string $c) => ['type' => 'class', 'value' => $c], self::DEFAULT_GROUPS[$name])
                : []);
            foreach ($members as $member) {
                $display = $member['type'] === 'class' ? $this->shortName($member['value']) : $member['value'];
                $result[] = $display;
                if ($member['type'] === 'alias') {
                    $queue[] = $member['value'];
                }
            }
        }
        return array_values(array_unique($result));
    }

    /**
     * @param string[] $routeFiles relative paths of files that produced endpoints
     * @return array<string, array<int, array{source: string, prefix: string, middleware: string[]}>>
     */
    private function resolveMountTargets(array $routeFiles): array
    {
        $byTarget = [];
        foreach ($this->mounts as $mount) {
            $candidates = array_values(array_filter(
                $routeFiles,
                fn(string $file) => $file === $mount['path'] || str_ends_with($file, '/' . $mount['path']),
            ));
            if ($candidates === []) {
                continue;
            }
            // Prefer the candidate closest to the mounting file (module providers mount their own routes).
            usort($candidates, function (string $a, string $b) use ($mount) {
                $common = $this->commonDirDepth($b, $mount['source']) <=> $this->commonDirDepth($a, $mount['source']);
                return $common !== 0 ? $common : strlen($a) <=> strlen($b);
            });
            $byTarget[$candidates[0]][] = [
                'source' => $mount['source'],
                'prefix' => $mount['prefix'],
                'middleware' => $mount['middleware'],
            ];
        }
        return $byTarget;
    }

    /**
     * Mounts of a file, composed with the mounts of the file that mounts it (require chains).
     *
     * @param array<string, array<int, array{source: string, prefix: string, middleware: string[]}>> $byTarget
     * @param array<string, bool> $visiting
     * @return array<int, array{prefix: string, middleware: string[]}>
     */
    private function effectiveMounts(string $file, array $byTarget, array $visiting): array
    {
        if (!isset($byTarget[$file]) || isset($visiting[$file])) {
            return [['prefix' => '', 'middleware' => []]];
        }
        $visiting[$file] = true;

        $result = [];
        foreach ($byTarget[$file] as $mount) {
            foreach ($this->effectiveMounts($mount['source'], $byTarget, $visiting) as $parent) {
                $prefix = trim(trim($parent['prefix'], '/') . '/' . trim($mount['prefix'], '/'), '/');
                $result[] = [
                    'prefix' => $prefix === '' ? '' : '/' . $prefix,
                    'middleware' => array_values(array_unique(array_merge($parent['middleware'], $mount['middleware']))),
                ];
            }
        }
        return $result;
    }

    private function isAuthReference(string $reference, array $visiting): bool
    {
        $lower = strtolower(ltrim($reference, '\\'));
        if (!str_contains($lower, '\\')) {
            // Alias pointing at another alias/group, or a class referenced by short name.
            if (isset($this->aliases[$lower]) || isset($this->groups[$lower])) {
                return $this->isAuthMiddleware($reference, $visiting);
            }
            foreach (array_keys($this->authClasses()) as $class) {
                if ($this->shortName($class) === $lower && $this->authClasses()[$class]) {
                    return true;
                }
            }
            return in_array($lower, self::KNOWN_AUTH_CLASSES, true);
        }
        return $this->authClasses()[$lower] ?? in_array($this->shortName($lower), self::KNOWN_AUTH_CLASSES, true);
    }

    /**
     * @return array<string, bool>
     */
    private function authClasses(): array
    {
        if ($this->authClassCache !== null) {
            return $this->authClassCache;
        }
        $cache = [];
        foreach (array_keys($this->middlewareClasses) as $class) {
            $cache[$class] = $this->classIsAuth($class, []);
        }
        return $this->authClassCache = $cache;
    }

    private function classIsAuth(string $class, array $visiting): bool
    {
        if (isset($visiting[$class])) {
            return false;
        }
        $visiting[$class] = true;
        $facts = $this->middlewareClasses[$class] ?? null;
        if ($facts === null) {
            return in_array($this->shortName($class), self::KNOWN_AUTH_CLASSES, true);
        }
        if ($facts['auth']) {
            return true;
        }
        foreach ($facts['delegates'] as $delegate) {
            if ($this->classIsAuth(strtolower($delegate), $visiting)) {
                return true;
            }
        }
        return $facts['extends'] !== null && $this->classIsAuth(strtolower($facts['extends']), $visiting);
    }

    // -------------------------------------------------------------------------
    // Controllers
    // -------------------------------------------------------------------------

    /**
     * @param Node[] $ast
     */
    private function collectImports(array $ast, string $relativePath): void
    {
        $map = [];
        $finder = new NodeFinder();
        foreach ($finder->findInstanceOf($ast, Stmt\Use_::class) as $use) {
            if ($use->type !== Stmt\Use_::TYPE_NORMAL && $use->type !== Stmt\Use_::TYPE_UNKNOWN) {
                continue;
            }
            foreach ($use->uses as $item) {
                $map[strtolower($item->getAlias()->toString())] = $item->name->toString();
            }
        }
        foreach ($finder->findInstanceOf($ast, Stmt\GroupUse::class) as $group) {
            foreach ($group->uses as $item) {
                $map[strtolower($item->getAlias()->toString())] = $group->prefix->toString() . '\\' . $item->name->toString();
            }
        }
        if ($map !== []) {
            $this->imports[$relativePath] = $map;
        }
    }

    private function collectControllerClass(Stmt\Class_ $class, string $relativePath): void
    {
        $fqn = $this->classFqn($class);
        if ($fqn === null) {
            return;
        }

        $authorize = $class->getMethod('authorize');
        if ($authorize !== null && !$authorize->isStatic() && $class->extends !== null) {
            $this->formRequests[strtolower($fqn)] = [
                'denies' => $this->inlineAuth->authorizeMethodDenies($authorize),
                'extends' => strtolower($this->resolvedName($class->extends)),
            ];
        } elseif ($class->extends !== null) {
            // Inherits authorize() from a project base request, if any.
            $this->formRequests[strtolower($fqn)] ??= ['denies' => false, 'extends' => strtolower($this->resolvedName($class->extends))];
        }

        // Inline enforcement per method, including private helpers (authorizeSignup(), gatewayClaims()).
        $enforces = [];
        $helperCalls = [];
        foreach ($class->getMethods() as $method) {
            $name = strtolower($method->name->toString());
            $enforces[$name] = $this->inlineAuth->enforcesAuth($method->stmts ?? []);
            $helperCalls[$name] = $this->inlineAuth->calledOwnMethods($method->stmts ?? []);
        }

        $methods = [];
        $middleware = [];
        $resourceAuthorized = false;
        foreach ($class->getMethods() as $method) {
            $name = strtolower($method->name->toString());
            if ($name === '__construct') {
                $middleware = array_merge($middleware, $this->constructorMiddleware($method));
                $resourceAuthorized = $resourceAuthorized || $this->callsThis($method, 'authorizeresource');
                continue;
            }
            if ($name === 'middleware' && $method->isStatic()) {
                // Laravel 11+ HasMiddleware::middleware(): ['auth', new Middleware('auth', only: [...])]
                $middleware = array_merge($middleware, $this->staticMiddleware($method));
                continue;
            }
            if (!$method->isPublic() || $method->isStatic()) {
                continue;
            }
            $abilities = $this->gateAbilities($method);
            // Inline enforcement: rejects with 401/403 based on the authenticated identity or a credential,
            // directly or through a helper of the same class. A comparison against request-supplied ids
            // alone (user_uuid === ...) does not count.
            if ($abilities === [] && $this->enforcesThroughHelpers($name, $enforces, $helperCalls, [])) {
                $abilities[] = 'inline-check';
            }
            $methods[$name] = [
                'line' => $method->getStartLine(),
                'file' => $relativePath,
                'abilities' => $abilities,
                'params' => $this->parameterClasses($method),
            ];
        }

        if ($methods === [] && $middleware === []) {
            return;
        }

        $key = strtolower($fqn);
        $this->classes[$key] = [
            'fqn' => $fqn,
            'file' => $relativePath,
            'extends' => $class->extends !== null ? strtolower($this->resolvedName($class->extends)) : null,
            'middleware' => $middleware,
            'resourceAuthorized' => $resourceAuthorized,
            'methods' => $methods,
        ];
        $this->shortIndex[strtolower($this->shortName($fqn))][] = $key;
    }

    /**
     * @param array<string, bool> $enforces
     * @param array<string, string[]> $helperCalls
     * @param array<string, bool> $visiting
     */
    private function enforcesThroughHelpers(string $method, array $enforces, array $helperCalls, array $visiting): bool
    {
        if (isset($visiting[$method]) || !isset($enforces[$method])) {
            return false;
        }
        if ($enforces[$method]) {
            return true;
        }
        $visiting[$method] = true;
        foreach ($helperCalls[$method] ?? [] as $helper) {
            if ($this->enforcesThroughHelpers($helper, $enforces, $helperCalls, $visiting)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Class-typed parameters of an action (resolved FQNs): candidates for FormRequests.
     *
     * @return string[]
     */
    private function parameterClasses(Stmt\ClassMethod $method): array
    {
        $classes = [];
        foreach ($method->params as $param) {
            if ($param->type instanceof Node\Name) {
                $classes[] = $this->resolvedName($param->type);
            }
        }
        return $classes;
    }

    /**
     * Whether a FormRequest (or a project base request it extends) declares an authorize() that can deny.
     */
    private function formRequestDenies(string $class, array $visiting): bool
    {
        if (isset($visiting[$class]) || !isset($this->formRequests[$class])) {
            return false;
        }
        $visiting[$class] = true;
        $facts = $this->formRequests[$class];
        return $facts['denies'] || ($facts['extends'] !== null && $this->formRequestDenies($facts['extends'], $visiting));
    }

    /**
     * $this->middleware('auth'), $this->middleware('auth', ['only' => [...]]), $this->middleware('auth')->except('index')
     *
     * @return array<int, array{name: string, only: ?string[], except: string[]}>
     */
    private function constructorMiddleware(Stmt\ClassMethod $constructor): array
    {
        $finder = new NodeFinder();
        $calls = $finder->findInstanceOf($constructor->stmts ?? [], Expr\MethodCall::class);

        $registrations = [];
        foreach ($calls as $call) {
            if (!$call->name instanceof Node\Identifier || strtolower($call->name->toString()) !== 'middleware'
                || !$call->var instanceof Expr\Variable || $call->var->name !== 'this') {
                continue;
            }
            $args = $this->callArgs($call);
            if ($args === []) {
                continue;
            }
            $only = null;
            $except = [];
            if (isset($args[1]) && $args[1]->value instanceof Expr\Array_) {
                foreach ($args[1]->value->items as $item) {
                    $key = $item?->key !== null ? $this->stringValue($item->key) : null;
                    if ($key === 'only') {
                        $only = $this->stringList($item->value);
                    } elseif ($key === 'except') {
                        $except = $this->stringList($item->value);
                    }
                }
            }
            // Chained ->only(...) / ->except(...) wrap this call.
            foreach ($calls as $outer) {
                if ($outer->var === $call && $outer->name instanceof Node\Identifier) {
                    $outerName = strtolower($outer->name->toString());
                    $outerArgs = $this->callArgs($outer);
                    if ($outerName === 'only' && isset($outerArgs[0])) {
                        $only = $this->stringList($outerArgs[0]->value);
                    } elseif ($outerName === 'except' && isset($outerArgs[0])) {
                        $except = array_merge($except, $this->stringList($outerArgs[0]->value));
                    }
                }
            }
            foreach ($this->middlewareNames($args[0]->value) as $name) {
                $registrations[] = ['name' => $name, 'only' => $only, 'except' => $except];
            }
        }
        return $registrations;
    }

    /**
     * @return array<int, array{name: string, only: ?string[], except: string[]}>
     */
    private function staticMiddleware(Stmt\ClassMethod $method): array
    {
        $finder = new NodeFinder();
        $registrations = [];
        foreach ($finder->findInstanceOf($method->stmts ?? [], Stmt\Return_::class) as $return) {
            if (!$return->expr instanceof Expr\Array_) {
                continue;
            }
            foreach ($return->expr->items as $item) {
                if ($item === null) {
                    continue;
                }
                $value = $item->value;
                if ($value instanceof Expr\New_ && !$value->isFirstClassCallable()) {
                    $args = $value->getArgs();
                    $only = null;
                    $except = [];
                    $names = [];
                    foreach ($args as $index => $arg) {
                        $argName = $arg->name?->toString();
                        if ($argName === 'only' || ($argName === null && $index === 1)) {
                            $only = $this->stringList($arg->value);
                        } elseif ($argName === 'except' || ($argName === null && $index === 2)) {
                            $except = $this->stringList($arg->value);
                        } elseif ($argName === 'middleware' || ($argName === null && $index === 0)) {
                            $names = $this->middlewareNames($arg->value);
                        }
                    }
                    foreach ($names as $name) {
                        $registrations[] = ['name' => $name, 'only' => $only, 'except' => $except];
                    }
                    continue;
                }
                foreach ($this->middlewareNames($value) as $name) {
                    $registrations[] = ['name' => $name, 'only' => null, 'except' => []];
                }
            }
        }
        return $registrations;
    }

    /**
     * Abilities enforced inside an action: Gate::authorize(), $this->authorize(), or a Gate/can() check
     * that guards an if / abort_if / abort_unless.
     *
     * @return string[]
     */
    private function gateAbilities(Stmt\ClassMethod $method): array
    {
        $finder = new NodeFinder();
        $stmts = $method->stmts ?? [];
        $abilities = [];

        $abilityOf = function (Expr\CallLike $call): string {
            $args = $this->callArgs($call);
            return isset($args[0]) ? ($this->stringValue($args[0]->value) ?? '*') : '*';
        };

        // Unconditional enforcement
        foreach ($finder->find($stmts, fn(Node $n) => $this->isEnforcingAuthorizeCall($n)) as $call) {
            $abilities[] = $abilityOf($call);
        }

        // Checks used as guards
        $guards = [];
        foreach ($finder->findInstanceOf($stmts, Stmt\If_::class) as $if) {
            $guards[] = $if->cond;
            foreach ($if->elseifs as $elseif) {
                $guards[] = $elseif->cond;
            }
        }
        foreach ($finder->findInstanceOf($stmts, Expr\FuncCall::class) as $call) {
            if ($call->name instanceof Node\Name
                && in_array(strtolower($call->name->getLast()), ['abort_if', 'abort_unless', 'throw_if', 'throw_unless'], true)
                && isset($this->callArgs($call)[0])) {
                $guards[] = $this->callArgs($call)[0]->value;
            }
        }
        foreach ($guards as $guard) {
            foreach ($finder->find([$guard], fn(Node $n) => $this->isGateCheckCall($n)) as $call) {
                $abilities[] = $abilityOf($call);
            }
        }

        return array_values(array_unique($abilities));
    }

    private function isEnforcingAuthorizeCall(Node $node): bool
    {
        if ($node instanceof Expr\StaticCall && $node->class instanceof Node\Name && $node->name instanceof Node\Identifier) {
            return strtolower($node->class->getLast()) === 'gate' && strtolower($node->name->toString()) === 'authorize';
        }
        if ($node instanceof Expr\MethodCall && $node->name instanceof Node\Identifier
            && $node->var instanceof Expr\Variable && $node->var->name === 'this') {
            return in_array(strtolower($node->name->toString()), ['authorize', 'authorizeforuser'], true);
        }
        return false;
    }

    private function isGateCheckCall(Node $node): bool
    {
        if ($node instanceof Expr\StaticCall && $node->class instanceof Node\Name && $node->name instanceof Node\Identifier) {
            return strtolower($node->class->getLast()) === 'gate'
                && in_array(strtolower($node->name->toString()), ['allows', 'denies', 'check', 'any', 'none', 'authorize'], true);
        }
        if (($node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall) && $node->name instanceof Node\Identifier) {
            return in_array(strtolower($node->name->toString()), ['can', 'cannot', 'cant'], true);
        }
        return false;
    }

    private function callsThis(Stmt\ClassMethod $method, string $name): bool
    {
        return (new NodeFinder())->findFirst($method->stmts ?? [], fn(Node $n) => $n instanceof Expr\MethodCall
            && $n->var instanceof Expr\Variable && $n->var->name === 'this'
            && $n->name instanceof Node\Identifier && strtolower($n->name->toString()) === $name) !== null;
    }

    /**
     * Resolve a route's controller reference to an indexed class, using the route file's imports.
     */
    private function resolveController(?string $controllerName, string $routeFile): ?string
    {
        if ($controllerName === null || $controllerName === '') {
            return null;
        }
        $name = ltrim($controllerName, '\\');
        $segments = explode('\\', $name);
        $imports = $this->imports[$routeFile] ?? [];
        $first = strtolower($segments[0]);
        if (isset($imports[$first])) {
            $segments[0] = $imports[$first];
            $name = implode('\\', $segments);
        }

        $lower = strtolower($name);
        if (isset($this->classes[$lower])) {
            return $lower;
        }

        $candidates = array_values(array_filter(
            $this->shortIndex[strtolower(end($segments))] ?? [],
            fn(string $fqn) => $fqn === $lower || str_ends_with($fqn, '\\' . $lower),
        ));
        if ($candidates === []) {
            return null;
        }
        // Closest to the root controller namespace wins (App\Http\Controllers\X over ...\V1\X).
        usort($candidates, fn(string $a, string $b) => substr_count($a, '\\') <=> substr_count($b, '\\') ?: strlen($a) <=> strlen($b));
        return $candidates[0];
    }

    /**
     * @return string[]
     */
    private function controllerMiddlewareFor(string $class, string $action, array $visiting): array
    {
        if (isset($visiting[$class]) || !isset($this->classes[$class])) {
            return [];
        }
        $visiting[$class] = true;
        $facts = $this->classes[$class];
        $names = [];
        foreach ($facts['middleware'] as $registration) {
            $only = $registration['only'] !== null ? array_map('strtolower', $registration['only']) : null;
            $except = array_map('strtolower', $registration['except']);
            if (($only === null || in_array($action, $only, true)) && !in_array($action, $except, true)) {
                $names[] = $registration['name'];
            }
        }
        if ($facts['extends'] !== null) {
            $names = array_merge($this->controllerMiddlewareFor($facts['extends'], $action, $visiting), $names);
        }
        return array_values(array_unique($names));
    }

    /**
     * @return array{line: int, file: string, abilities: string[], params: string[]}|null
     */
    private function findMethod(string $class, string $action, array $visiting): ?array
    {
        if (isset($visiting[$class]) || !isset($this->classes[$class])) {
            return null;
        }
        $visiting[$class] = true;
        $facts = $this->classes[$class];
        if (isset($facts['methods'][$action])) {
            return $facts['methods'][$action];
        }
        return $facts['extends'] !== null ? $this->findMethod($facts['extends'], $action, $visiting) : null;
    }

    private function resourceAuthorized(string $class, array $visiting): bool
    {
        if (isset($visiting[$class]) || !isset($this->classes[$class])) {
            return false;
        }
        $visiting[$class] = true;
        return $this->classes[$class]['resourceAuthorized']
            || ($this->classes[$class]['extends'] !== null && $this->resourceAuthorized($this->classes[$class]['extends'], $visiting));
    }

    /**
     * Roles implied by custom auth middleware: auth.entity:agent,pro => [agent, pro]; auth.agent => [agent].
     * Built-in guards (auth:api, auth:sanctum) name a guard, not a role, and are skipped.
     *
     * @param string[] $middleware
     * @return string[]
     */
    private function rolesFromMiddleware(array $middleware): array
    {
        $roles = [];
        foreach ($middleware as $name) {
            [$base, $params] = array_pad(explode(':', $name, 2), 2, null);
            $base = strtolower(trim($base));
            if (in_array($base, ['auth', 'auth.basic', 'auth.session', 'can', 'role', 'permission', 'verified', 'guest'], true)
                || !$this->isAuthMiddleware($name)) {
                continue;
            }
            if ($params !== null && trim($params) !== '') {
                foreach (preg_split('/[,|]/', $params) ?: [] as $role) {
                    if (trim($role) !== '') {
                        $roles[] = trim($role);
                    }
                }
            } elseif (str_starts_with($base, 'auth.')) {
                $roles[] = substr($base, 5);
            }
        }
        return $roles;
    }

    /**
     * @param string[] $middleware
     */
    private function anyAuth(array $middleware): bool
    {
        foreach ($middleware as $name) {
            if ($this->isAuthMiddleware($name)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return string[]
     */
    private function middlewareNames(Node $value): array
    {
        if ($value instanceof Expr\Array_) {
            $names = [];
            foreach ($value->items as $item) {
                if ($item !== null) {
                    $names = array_merge($names, $this->middlewareNames($item->value));
                }
            }
            return $names;
        }
        $ref = $this->middlewareReference($value);
        if ($ref === null) {
            return [];
        }
        return [$ref['type'] === 'class' ? $ref['value'] : $ref['value']];
    }

    /**
     * @return string[]
     */
    private function stringList(Node $value): array
    {
        if ($value instanceof Expr\Array_) {
            $list = [];
            foreach ($value->items as $item) {
                $string = $item !== null ? $this->stringValue($item->value) : null;
                if ($string !== null) {
                    $list[] = $string;
                }
            }
            return $list;
        }
        $string = $this->stringValue($value);
        return $string !== null ? [$string] : [];
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function classFqn(Stmt\Class_ $class): ?string
    {
        // php-parser 5 exposes the NameResolver result as a property, older versions as an attribute.
        $namespaced = property_exists($class, 'namespacedName') ? $class->namespacedName : $class->getAttribute('namespacedName');
        if ($namespaced instanceof Node\Name) {
            return $namespaced->toString();
        }
        return $class->name?->toString();
    }

    private function resolvedName(Node\Name $name): string
    {
        $resolved = $name->getAttribute('resolvedName');
        return $resolved instanceof Node\Name ? $resolved->toString() : $name->toString();
    }

    private function stringValue(Node $node): ?string
    {
        return $node instanceof Node\Scalar\String_ ? $node->value : null;
    }

    private function shortName(string $class): string
    {
        $parts = explode('\\', $class);
        return strtolower(end($parts)) === strtolower($class) && !str_contains($class, '\\')
            ? $class
            : (string) end($parts);
    }

    private function relativePath(string $path, string $root): string
    {
        $normalized = str_replace('\\', '/', $path);
        if ($root !== '' && str_starts_with($normalized, $root . '/')) {
            return substr($normalized, strlen($root) + 1);
        }
        return ltrim($normalized, '/');
    }

    private function commonDirDepth(string $a, string $b): int
    {
        $da = explode('/', dirname($a));
        $db = explode('/', dirname($b));
        $depth = 0;
        while (isset($da[$depth], $db[$depth]) && $da[$depth] === $db[$depth] && $da[$depth] !== '.') {
            $depth++;
        }
        return $depth;
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
