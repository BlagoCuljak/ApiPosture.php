<?php

declare(strict_types=1);

namespace ApiPosture\Core\Model;

final class AuthorizationInfo
{
    /**
     * @param string[] $roles
     * @param string[] $policies
     * @param string[] $middleware
     */
    public function __construct(
        public readonly bool $hasAuth = false,
        public readonly bool $hasAllowAnonymous = false,
        public readonly array $roles = [],
        public readonly array $policies = [],
        public readonly array $middleware = [],
        public readonly ?string $inheritedFrom = null,
    ) {}

    public function toArray(): array
    {
        return [
            'hasAuth' => $this->hasAuth,
            'hasAllowAnonymous' => $this->hasAllowAnonymous,
            'roles' => $this->roles,
            'policies' => $this->policies,
            'middleware' => $this->middleware,
            'inheritedFrom' => $this->inheritedFrom,
        ];
    }
}
