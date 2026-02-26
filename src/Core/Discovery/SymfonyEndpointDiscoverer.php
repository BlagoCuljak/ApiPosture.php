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

final class SymfonyEndpointDiscoverer implements EndpointDiscovererInterface
{
    private const ROUTE_ATTRIBUTES = [
        'Route',
        'Symfony\\Component\\Routing\\Annotation\\Route',
        'Symfony\\Component\\Routing\\Attribute\\Route',
    ];

    private const SECURITY_ATTRIBUTES = [
        'IsGranted',
        'Symfony\\Component\\Security\\Http\\Attribute\\IsGranted',
        'Security',
        'Sensio\\Bundle\\FrameworkExtraBundle\\Configuration\\Security',
        'Symfony\\Component\\ExpressionLanguage\\Attribute\\Security',
    ];

    public function supports(array $ast, string $filePath): bool
    {
        $finder = new NodeFinder();
        $classes = $finder->findInstanceOf($ast, Stmt\Class_::class);

        foreach ($classes as $class) {
            if ($this->isSymfonyController($class)) {
                return true;
            }

            // Check for #[Route] attributes on class or methods
            if ($this->hasRouteAttributes($class)) {
                return true;
            }
        }

        return false;
    }

    public function discover(array $ast, string $filePath): array
    {
        $endpoints = [];
        $finder = new NodeFinder();
        $classes = $finder->findInstanceOf($ast, Stmt\Class_::class);

        foreach ($classes as $class) {
            if (!$this->isSymfonyController($class) && !$this->hasRouteAttributes($class)) {
                continue;
            }

            $className = $class->name?->toString() ?? 'Unknown';
            $classPrefix = $this->getClassRoutePrefix($class);
            $classSecurity = $this->getClassSecurityInfo($class);

            foreach ($class->getMethods() as $method) {
                if (!$method->isPublic()) {
                    continue;
                }

                $routeInfos = $this->getMethodRouteAttributes($method);
                if (empty($routeInfos)) {
                    continue;
                }

                $methodSecurity = $this->getMethodSecurityInfo($method);
                $authInfo = $this->mergeSecurityInfo($classSecurity, $methodSecurity);

                foreach ($routeInfos as $routeInfo) {
                    $fullPath = $classPrefix
                        ? rtrim($classPrefix, '/') . '/' . ltrim($routeInfo['path'], '/')
                        : $routeInfo['path'];

                    $endpoints[] = new Endpoint(
                        route: $fullPath,
                        methods: $routeInfo['methods'],
                        type: EndpointType::Annotation,
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

    private function isSymfonyController(Stmt\Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $parentName = $class->extends->toString();
        return $parentName === 'AbstractController'
            || str_ends_with($parentName, '\\AbstractController')
            || str_ends_with($parentName, 'Controller');
    }

    private function hasRouteAttributes(Stmt\Class_ $class): bool
    {
        foreach ($class->attrGroups as $attrGroup) {
            foreach ($attrGroup->attrs as $attr) {
                if ($this->isRouteAttribute($attr)) {
                    return true;
                }
            }
        }

        foreach ($class->getMethods() as $method) {
            foreach ($method->attrGroups as $attrGroup) {
                foreach ($attrGroup->attrs as $attr) {
                    if ($this->isRouteAttribute($attr)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private function isRouteAttribute(Node\Attribute $attr): bool
    {
        $name = $attr->name->toString();
        foreach (self::ROUTE_ATTRIBUTES as $routeAttr) {
            if ($name === $routeAttr || str_ends_with($name, '\\' . $routeAttr)) {
                return true;
            }
        }
        return $name === 'Route';
    }

    private function isSecurityAttribute(Node\Attribute $attr): bool
    {
        $name = $attr->name->toString();
        foreach (self::SECURITY_ATTRIBUTES as $secAttr) {
            if ($name === $secAttr || str_ends_with($name, '\\' . $secAttr)) {
                return true;
            }
        }
        return false;
    }

    private function getClassRoutePrefix(Stmt\Class_ $class): ?string
    {
        foreach ($class->attrGroups as $attrGroup) {
            foreach ($attrGroup->attrs as $attr) {
                if ($this->isRouteAttribute($attr)) {
                    return $this->extractRoutePath($attr);
                }
            }
        }
        return null;
    }

    /**
     * @return array{roles: string[], policies: string[], hasAuth: bool, hasAllowAnonymous: bool}
     */
    private function getClassSecurityInfo(Stmt\Class_ $class): array
    {
        return $this->extractSecurityFromAttributes($class->attrGroups);
    }

    /**
     * @return array{roles: string[], policies: string[], hasAuth: bool, hasAllowAnonymous: bool}
     */
    private function getMethodSecurityInfo(Stmt\ClassMethod $method): array
    {
        return $this->extractSecurityFromAttributes($method->attrGroups);
    }

    /**
     * @param Node\AttributeGroup[] $attrGroups
     * @return array{roles: string[], policies: string[], hasAuth: bool, hasAllowAnonymous: bool}
     */
    private function extractSecurityFromAttributes(array $attrGroups): array
    {
        $roles = [];
        $policies = [];
        $hasAuth = false;
        $hasAllowAnonymous = false;

        foreach ($attrGroups as $attrGroup) {
            foreach ($attrGroup->attrs as $attr) {
                if (!$this->isSecurityAttribute($attr)) {
                    continue;
                }

                $name = $attr->name->toString();
                $shortName = class_exists($name) ? (new \ReflectionClass($name))->getShortName() : basename(str_replace('\\', '/', $name));

                if ($shortName === 'IsGranted' || $name === 'IsGranted') {
                    $hasAuth = true;
                    $grantedValue = $this->extractFirstStringArg($attr);
                    if ($grantedValue !== null) {
                        if (str_starts_with($grantedValue, 'ROLE_')) {
                            $roles[] = $grantedValue;
                        } else {
                            $policies[] = $grantedValue;
                        }
                    }
                } elseif ($shortName === 'Security' || $name === 'Security') {
                    $hasAuth = true;
                    $securityExpr = $this->extractFirstStringArg($attr);
                    if ($securityExpr !== null) {
                        // Parse roles from security expressions like "is_granted('ROLE_ADMIN')"
                        if (preg_match_all("/ROLE_[A-Z_]+/", $securityExpr, $matches)) {
                            $roles = array_merge($roles, $matches[0]);
                        }
                        // Check for IS_AUTHENTICATED_ANONYMOUSLY
                        if (str_contains($securityExpr, 'IS_AUTHENTICATED_ANONYMOUSLY')
                            || str_contains($securityExpr, 'PUBLIC_ACCESS')) {
                            $hasAllowAnonymous = true;
                            $hasAuth = false;
                        }
                    }
                }
            }
        }

        return [
            'roles' => array_unique($roles),
            'policies' => array_unique($policies),
            'hasAuth' => $hasAuth,
            'hasAllowAnonymous' => $hasAllowAnonymous,
        ];
    }

    private function mergeSecurityInfo(array $classSecurity, array $methodSecurity): AuthorizationInfo
    {
        $hasAuth = $classSecurity['hasAuth'] || $methodSecurity['hasAuth'];
        $hasAllowAnonymous = $methodSecurity['hasAllowAnonymous']
            || ($classSecurity['hasAllowAnonymous'] && !$methodSecurity['hasAuth']);

        $roles = array_unique(array_merge($classSecurity['roles'], $methodSecurity['roles']));
        $policies = array_unique(array_merge($classSecurity['policies'], $methodSecurity['policies']));

        $inheritedFrom = null;
        if ($classSecurity['hasAuth'] && !$methodSecurity['hasAuth'] && !$methodSecurity['hasAllowAnonymous']) {
            $inheritedFrom = 'class';
        }

        return new AuthorizationInfo(
            hasAuth: $hasAuth,
            hasAllowAnonymous: $hasAllowAnonymous,
            roles: $roles,
            policies: $policies,
            middleware: [],
            inheritedFrom: $inheritedFrom,
        );
    }

    /**
     * @return array<array{path: string, methods: HttpMethod[]}>
     */
    private function getMethodRouteAttributes(Stmt\ClassMethod $method): array
    {
        $routes = [];

        foreach ($method->attrGroups as $attrGroup) {
            foreach ($attrGroup->attrs as $attr) {
                if (!$this->isRouteAttribute($attr)) {
                    continue;
                }

                $path = $this->extractRoutePath($attr);
                if ($path === null) {
                    continue;
                }

                $methods = $this->extractRouteMethods($attr);

                $routes[] = [
                    'path' => $path,
                    'methods' => $methods,
                ];
            }
        }

        return $routes;
    }

    private function extractRoutePath(Node\Attribute $attr): ?string
    {
        foreach ($attr->args as $i => $arg) {
            // First positional arg or named 'path'/'uri' arg
            if ($arg->name === null && $i === 0) {
                if ($arg->value instanceof Node\Scalar\String_) {
                    return $arg->value->value;
                }
            } elseif ($arg->name?->toString() === 'path' || $arg->name?->toString() === 'uri') {
                if ($arg->value instanceof Node\Scalar\String_) {
                    return $arg->value->value;
                }
            }
        }
        return null;
    }

    /**
     * @return HttpMethod[]
     */
    private function extractRouteMethods(Node\Attribute $attr): array
    {
        foreach ($attr->args as $arg) {
            if ($arg->name?->toString() === 'methods') {
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
                    if (!empty($methods)) {
                        return $methods;
                    }
                }
            }
        }

        // Default to GET if no methods specified
        return [HttpMethod::GET];
    }

    private function extractFirstStringArg(Node\Attribute $attr): ?string
    {
        foreach ($attr->args as $arg) {
            if ($arg->value instanceof Node\Scalar\String_) {
                return $arg->value->value;
            }
        }
        return null;
    }
}
