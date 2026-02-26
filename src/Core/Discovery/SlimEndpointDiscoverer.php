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

final class SlimEndpointDiscoverer implements EndpointDiscovererInterface
{
    private const ROUTE_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'any', 'map'];

    public function supports(array $ast, string $filePath): bool
    {
        $finder = new NodeFinder();

        // Look for $app->get(), $app->post(), etc.
        $routeCalls = $finder->find($ast, function (Node $node) {
            return $this->isSlimRouteCall($node);
        });

        if (count($routeCalls) > 0) {
            return true;
        }

        // Look for $app->group() or Slim\App usage
        $groupCalls = $finder->find($ast, function (Node $node) {
            return $node instanceof Expr\MethodCall
                && $node->name instanceof Node\Identifier
                && $node->name->toString() === 'group'
                && count($node->getArgs()) >= 2
                && $this->isSlimRoutePath($node->getArgs()[0]->value);
        });

        return count($groupCalls) > 0;
    }

    public function discover(array $ast, string $filePath): array
    {
        $endpoints = [];
        $finder = new NodeFinder();

        // Find all route-defining method calls
        $routeCalls = $finder->find($ast, function (Node $node) {
            return $this->isSlimRouteCall($node);
        });

        // Find group calls for prefix resolution
        $groups = $this->findGroups($ast, $finder);

        foreach ($routeCalls as $call) {
            $endpoint = $this->parseRouteCall($call, $filePath, $groups);
            if ($endpoint !== null) {
                $endpoints[] = $endpoint;
            }
        }

        return $endpoints;
    }

    private function isSlimRouteCall(Node $node): bool
    {
        if (!$node instanceof Expr\MethodCall) {
            return false;
        }

        if (!$node->name instanceof Node\Identifier) {
            return false;
        }

        $methodName = strtolower($node->name->toString());
        if (!in_array($methodName, self::ROUTE_METHODS, true)) {
            return false;
        }

        $args = $node->getArgs();

        // map() signature: map(array $methods, string $path, callable $handler)
        if ($methodName === 'map') {
            return count($args) >= 3
                && $args[0]->value instanceof Expr\Array_
                && $this->isSlimRoutePath($args[1]->value);
        }

        // All other methods: get/post/put/delete/patch/any
        // Signature: (string $path, handler), always 2+ args
        return count($args) >= 2
            && $this->isSlimRoutePath($args[0]->value);
    }

    private function isSlimRoutePath(Node $node): bool
    {
        if (!$node instanceof Node\Scalar\String_) {
            return false;
        }

        // Slim route patterns are always either empty (used inside groups)
        // or start with '/' - this is the only way to define a route.
        return $node->value === '' || str_starts_with($node->value, '/');
    }

    private function parseRouteCall(Expr\MethodCall $call, string $filePath, array $groups): ?Endpoint
    {
        $methodName = strtolower($call->name->toString());
        $args = $call->getArgs();

        if (count($args) < 1) {
            return null;
        }

        $path = null;
        if ($methodName === 'map') {
            if (isset($args[1]) && $args[1]->value instanceof Node\Scalar\String_) {
                $path = $args[1]->value->value;
            }
        } elseif ($args[0]->value instanceof Node\Scalar\String_) {
            $path = $args[0]->value->value;
        }

        if ($path === null) {
            return null;
        }

        $httpMethods = match ($methodName) {
            'get' => [HttpMethod::GET],
            'post' => [HttpMethod::POST],
            'put' => [HttpMethod::PUT],
            'delete' => [HttpMethod::DELETE],
            'patch' => [HttpMethod::PATCH],
            'any' => [HttpMethod::GET, HttpMethod::POST, HttpMethod::PUT, HttpMethod::DELETE, HttpMethod::PATCH],
            'map' => $this->resolveMapMethods($call),
            default => null,
        };

        if ($httpMethods === null) {
            return null;
        }

        // Resolve prefix from enclosing groups
        $prefix = $this->resolveGroupPrefix($call, $groups);
        $fullPath = $prefix ? rtrim($prefix, '/') . '/' . ltrim($path, '/') : $path;

        // Check for middleware (->add() calls chained after the route)
        $middleware = $this->resolveMiddleware($call, $groups);
        $authInfo = $this->resolveAuthFromMiddleware($middleware);

        return new Endpoint(
            route: $fullPath,
            methods: $httpMethods,
            type: EndpointType::Route,
            location: new SourceLocation($filePath, $call->getStartLine()),
            authorization: $authInfo,
        );
    }

    /**
     * @return HttpMethod[]|null
     */
    private function resolveMapMethods(Expr\MethodCall $call): ?array
    {
        $args = $call->getArgs();
        // map() first arg is methods array, second is path
        if (count($args) < 2) {
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
                }
            }
        }

        return count($methods) > 0 ? $methods : null;
    }

    /**
     * @return array<array{prefix: string, middleware: string[], startLine: int, endLine: int}>
     */
    private function findGroups(array $ast, NodeFinder $finder): array
    {
        $groups = [];

        $groupCalls = $finder->find($ast, function (Node $node) {
            return $node instanceof Expr\MethodCall
                && $node->name instanceof Node\Identifier
                && $node->name->toString() === 'group';
        });

        foreach ($groupCalls as $groupCall) {
            $args = $groupCall->getArgs();
            if (count($args) < 1) {
                continue;
            }

            $prefix = '';
            if ($args[0]->value instanceof Node\Scalar\String_) {
                $prefix = $args[0]->value->value;
            }

            // Find ->add() middleware on the group
            $middleware = $this->getAddMiddleware($groupCall);

            $groups[] = [
                'prefix' => $prefix,
                'middleware' => $middleware,
                'startLine' => $groupCall->getStartLine(),
                'endLine' => $groupCall->getEndLine(),
            ];
        }

        return $groups;
    }

    private function resolveGroupPrefix(Expr\MethodCall $call, array $groups): string
    {
        $line = $call->getStartLine();
        $prefix = '';

        foreach ($groups as $group) {
            if ($line >= $group['startLine'] && $line <= $group['endLine']) {
                $prefix = rtrim($prefix, '/') . '/' . ltrim($group['prefix'], '/');
            }
        }

        return $prefix;
    }

    /**
     * @return string[]
     */
    private function resolveMiddleware(Node $node, array $groups): array
    {
        $middleware = [];

        // Check chained ->add() calls
        $middleware = array_merge($middleware, $this->getAddMiddleware($node));

        // Check parent (if this call is inside a variable that had add() called)
        $line = $node->getStartLine();
        foreach ($groups as $group) {
            if ($line >= $group['startLine'] && $line <= $group['endLine']) {
                $middleware = array_merge($middleware, $group['middleware']);
            }
        }

        return array_unique($middleware);
    }

    /**
     * Look for ->add(new SomeMiddleware()) or ->add(SomeMiddleware::class) patterns.
     *
     * @return string[]
     */
    private function getAddMiddleware(Node $node): array
    {
        $middleware = [];

        // Walk up looking for nodes that are the var of an add() call
        // This handles: $app->get('/path', handler)->add(new AuthMiddleware())
        // Since we have the inner get() call, we can't easily walk up.
        // Instead, look at the parent context.

        // Check if this node is wrapped in method calls
        if ($node instanceof Expr\MethodCall && $node->name instanceof Node\Identifier) {
            $name = $node->name->toString();
            if ($name === 'add') {
                $middleware = array_merge($middleware, $this->extractAddArgs($node));
                // Recurse to find chained add() calls
                if ($node->var instanceof Expr\MethodCall) {
                    $middleware = array_merge($middleware, $this->getAddMiddleware($node->var));
                }
            }
        }

        return $middleware;
    }

    /**
     * @return string[]
     */
    private function extractAddArgs(Expr\MethodCall $call): array
    {
        $middleware = [];
        foreach ($call->getArgs() as $arg) {
            if ($arg->value instanceof Expr\New_) {
                if ($arg->value->class instanceof Node\Name) {
                    $middleware[] = $arg->value->class->toString();
                }
            } elseif ($arg->value instanceof Expr\ClassConstFetch) {
                if ($arg->value->class instanceof Node\Name) {
                    $middleware[] = $arg->value->class->toString();
                }
            } elseif ($arg->value instanceof Node\Scalar\String_) {
                $middleware[] = $arg->value->value;
            }
        }
        return $middleware;
    }

    /**
     * @param string[] $middleware
     */
    private function resolveAuthFromMiddleware(array $middleware): AuthorizationInfo
    {
        $hasAuth = false;
        $roles = [];
        $policies = [];

        foreach ($middleware as $mw) {
            $mwLower = strtolower($mw);

            // Common auth middleware patterns
            if (str_contains($mwLower, 'auth')
                || str_contains($mwLower, 'jwt')
                || str_contains($mwLower, 'token')
                || str_contains($mwLower, 'session')) {
                $hasAuth = true;
            }

            // Role-based middleware
            if (str_contains($mwLower, 'role') || str_contains($mwLower, 'acl')) {
                $hasAuth = true;
            }

            // Permission-based middleware
            if (str_contains($mwLower, 'permission') || str_contains($mwLower, 'policy')) {
                $hasAuth = true;
            }
        }

        return new AuthorizationInfo(
            hasAuth: $hasAuth,
            hasAllowAnonymous: false,
            roles: $roles,
            policies: $policies,
            middleware: $middleware,
        );
    }
}
