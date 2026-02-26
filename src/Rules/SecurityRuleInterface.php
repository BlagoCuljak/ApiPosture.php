<?php

declare(strict_types=1);

namespace ApiPosture\Rules;

use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Finding;

interface SecurityRuleInterface
{
    public function getId(): string;

    public function getName(): string;

    /**
     * Evaluate the rule against a single endpoint.
     *
     * @return Finding[]
     */
    public function evaluate(Endpoint $endpoint): array;
}
