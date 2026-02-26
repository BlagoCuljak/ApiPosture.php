<?php

declare(strict_types=1);

namespace ApiPosture\Core\Model;

use ApiPosture\Core\Model\Enums\EndpointType;
use ApiPosture\Core\Model\Enums\HttpMethod;
use ApiPosture\Core\Model\Enums\SecurityClassification;

final class Endpoint
{
    /**
     * @param HttpMethod[] $methods
     */
    public function __construct(
        public readonly string $route,
        public readonly array $methods,
        public readonly EndpointType $type,
        public readonly SourceLocation $location,
        public readonly AuthorizationInfo $authorization,
        public SecurityClassification $classification = SecurityClassification::Public,
        public readonly ?string $controllerName = null,
        public readonly ?string $actionName = null,
    ) {}

    public function hasWriteMethods(): bool
    {
        foreach ($this->methods as $method) {
            if ($method->isWriteMethod()) {
                return true;
            }
        }
        return false;
    }

    public function methodsString(): string
    {
        return implode(', ', array_map(fn(HttpMethod $m) => $m->name, $this->methods));
    }

    public function toArray(): array
    {
        return [
            'route' => $this->route,
            'methods' => array_map(fn(HttpMethod $m) => $m->name, $this->methods),
            'type' => $this->type->value,
            'location' => $this->location->toArray(),
            'authorization' => $this->authorization->toArray(),
            'classification' => $this->classification->value,
            'controllerName' => $this->controllerName,
            'actionName' => $this->actionName,
        ];
    }
}
