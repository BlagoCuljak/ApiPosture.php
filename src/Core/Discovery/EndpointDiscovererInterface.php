<?php

declare(strict_types=1);

namespace ApiPosture\Core\Discovery;

use ApiPosture\Core\Model\Endpoint;
use PhpParser\Node\Stmt;

interface EndpointDiscovererInterface
{
    /**
     * Determine if this discoverer can handle the given AST.
     *
     * @param Stmt[] $ast
     */
    public function supports(array $ast, string $filePath): bool;

    /**
     * Discover endpoints from the given AST.
     *
     * @param Stmt[] $ast
     * @return Endpoint[]
     */
    public function discover(array $ast, string $filePath): array;
}
