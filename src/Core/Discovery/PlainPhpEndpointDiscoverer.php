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
use PhpParser\NodeFinder;

/**
 * Discovers endpoints in plain/vanilla PHP files that handle HTTP requests
 * directly via $_POST, $_GET, $_REQUEST, or $_SERVER['REQUEST_METHOD']
 * without any routing framework (no Laravel, Symfony, or Slim).
 */
final class PlainPhpEndpointDiscoverer implements EndpointDiscovererInterface
{
    /** $_SESSION key fragments that suggest an authenticated check */
    private const AUTH_SESSION_KEYS = ['user', 'auth', 'logged', 'login', 'uid', 'account', 'member'];

    public function supports(array $ast, string $filePath): bool
    {
        $finder = new NodeFinder();

        // Skip files that contain Laravel Route:: static calls
        $routeCalls = $finder->find($ast, function (Node $node) {
            return $node instanceof Expr\StaticCall
                && $node->class instanceof Node\Name
                && ($node->class->toString() === 'Route' || str_ends_with($node->class->toString(), '\\Route'));
        });

        if (!empty($routeCalls)) {
            return false;
        }

        // Look for HTTP superglobal accesses: $_POST, $_GET, $_REQUEST, $_SERVER
        $httpUsage = $finder->find($ast, function (Node $node) {
            return $this->isHttpSuperglobalAccess($node);
        });

        return !empty($httpUsage);
    }

    public function discover(array $ast, string $filePath): array
    {
        $methods = $this->inferMethods($ast);
        $authInfo = $this->inferAuthInfo($ast);
        $route = '/' . basename($filePath);

        return [new Endpoint(
            route: $route,
            methods: $methods,
            type: EndpointType::File,
            location: new SourceLocation($filePath, 1),
            authorization: $authInfo,
        )];
    }

    private function isHttpSuperglobalAccess(Node $node): bool
    {
        if (!$node instanceof Expr\Variable) {
            return false;
        }

        return in_array($node->name, ['_POST', '_GET', '_REQUEST', '_SERVER', '_FILES'], true);
    }

    /**
     * Infer HTTP methods from which superglobals are accessed and any
     * explicit $_SERVER['REQUEST_METHOD'] comparisons.
     *
     * @return HttpMethod[]
     */
    private function inferMethods(array $ast): array
    {
        $finder = new NodeFinder();
        $methods = [];

        // Check for explicit REQUEST_METHOD string comparisons:
        // e.g. $_SERVER['REQUEST_METHOD'] === 'POST'
        $requestMethodChecks = $finder->find($ast, function (Node $node) {
            return $this->isRequestMethodComparison($node);
        });

        foreach ($requestMethodChecks as $node) {
            $method = $this->extractMethodFromComparison($node);
            if ($method !== null && !in_array($method, $methods, true)) {
                $methods[] = $method;
            }
        }

        // Check for $_POST superglobal usage
        $postUsage = $finder->find($ast, function (Node $node) {
            return $node instanceof Expr\ArrayDimFetch
                && $node->var instanceof Expr\Variable
                && $node->var->name === '_POST';
        });

        if (!empty($postUsage) && !in_array(HttpMethod::POST, $methods, true)) {
            $methods[] = HttpMethod::POST;
        }

        // Check for $_FILES usage (file upload implies POST)
        $filesUsage = $finder->find($ast, function (Node $node) {
            return $node instanceof Expr\Variable && $node->name === '_FILES';
        });

        if (!empty($filesUsage) && !in_array(HttpMethod::POST, $methods, true)) {
            $methods[] = HttpMethod::POST;
        }

        // Check for $_GET superglobal usage
        $getUsage = $finder->find($ast, function (Node $node) {
            return $node instanceof Expr\ArrayDimFetch
                && $node->var instanceof Expr\Variable
                && $node->var->name === '_GET';
        });

        if (!empty($getUsage) && !in_array(HttpMethod::GET, $methods, true)) {
            $methods[] = HttpMethod::GET;
        }

        // Check for $_REQUEST (covers GET + POST)
        $requestUsage = $finder->find($ast, function (Node $node) {
            return $node instanceof Expr\ArrayDimFetch
                && $node->var instanceof Expr\Variable
                && $node->var->name === '_REQUEST';
        });

        if (!empty($requestUsage)) {
            if (!in_array(HttpMethod::GET, $methods, true)) {
                $methods[] = HttpMethod::GET;
            }
            if (!in_array(HttpMethod::POST, $methods, true)) {
                $methods[] = HttpMethod::POST;
            }
        }

        // Default to GET if no method-specific superglobal was found
        if (empty($methods)) {
            $methods = [HttpMethod::GET];
        }

        return $methods;
    }

    /**
     * Detects: $_SERVER['REQUEST_METHOD'] === 'POST' (and variants with ==, !==, !=)
     */
    private function isRequestMethodComparison(Node $node): bool
    {
        if (!$node instanceof Expr\BinaryOp\Identical
            && !$node instanceof Expr\BinaryOp\Equal
            && !$node instanceof Expr\BinaryOp\NotIdentical
            && !$node instanceof Expr\BinaryOp\NotEqual) {
            return false;
        }

        $sides = [$node->left, $node->right];
        foreach ($sides as $side) {
            if ($this->isServerRequestMethodFetch($side)) {
                return true;
            }
        }

        return false;
    }

    private function isServerRequestMethodFetch(Node $node): bool
    {
        return $node instanceof Expr\ArrayDimFetch
            && $node->var instanceof Expr\Variable
            && $node->var->name === '_SERVER'
            && $node->dim instanceof Node\Scalar\String_
            && $node->dim->value === 'REQUEST_METHOD';
    }

    private function extractMethodFromComparison(Node $node): ?HttpMethod
    {
        if (!$node instanceof Expr\BinaryOp) {
            return null;
        }

        $methodString = null;
        foreach ([$node->left, $node->right] as $side) {
            if ($side instanceof Node\Scalar\String_) {
                $methodString = strtoupper($side->value);
            }
        }

        if ($methodString === null) {
            return null;
        }

        try {
            return HttpMethod::fromString($methodString);
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    private function inferAuthInfo(array $ast): AuthorizationInfo
    {
        $finder = new NodeFinder();

        // Look for session-based auth checks: $_SESSION['user'], $_SESSION['logged_in'], etc.
        $sessionAuthChecks = $finder->find($ast, function (Node $node) {
            return $this->isSessionAuthKeyAccess($node);
        });

        $hasAuth = !empty($sessionAuthChecks);

        return new AuthorizationInfo(
            hasAuth: $hasAuth,
            hasAllowAnonymous: !$hasAuth,
            roles: [],
            policies: [],
            middleware: [],
        );
    }

    /**
     * Returns true if the node is a $_SESSION['<auth-related-key>'] access.
     */
    private function isSessionAuthKeyAccess(Node $node): bool
    {
        if (!$node instanceof Expr\ArrayDimFetch) {
            return false;
        }

        if (!$node->var instanceof Expr\Variable || $node->var->name !== '_SESSION') {
            return false;
        }

        if (!$node->dim instanceof Node\Scalar\String_) {
            return false;
        }

        $key = strtolower($node->dim->value);
        foreach (self::AUTH_SESSION_KEYS as $fragment) {
            if (str_contains($key, $fragment)) {
                return true;
            }
        }

        return false;
    }
}
