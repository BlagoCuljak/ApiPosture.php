<?php

declare(strict_types=1);

namespace ApiPosture\Core\Model;

use ApiPosture\Core\Model\Enums\Severity;

final class Finding
{
    public function __construct(
        public readonly string $ruleId,
        public readonly string $ruleName,
        public readonly Severity $severity,
        public readonly string $message,
        public readonly Endpoint $endpoint,
        public readonly string $recommendation = '',
    ) {}

    public function toArray(): array
    {
        return [
            'ruleId' => $this->ruleId,
            'ruleName' => $this->ruleName,
            'severity' => $this->severity->label(),
            'message' => $this->message,
            'endpoint' => $this->endpoint->toArray(),
            'recommendation' => $this->recommendation,
        ];
    }
}
