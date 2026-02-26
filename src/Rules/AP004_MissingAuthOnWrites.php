<?php

declare(strict_types=1);

namespace ApiPosture\Rules;

use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\Severity;
use ApiPosture\Core\Model\Finding;

/**
 * AP004: Write endpoints with zero authentication.
 *
 * Flags POST/PUT/DELETE/PATCH endpoints that have absolutely no auth middleware.
 * This is the most critical finding — unprotected writes.
 */
final class AP004_MissingAuthOnWrites implements SecurityRuleInterface
{
    public function getId(): string
    {
        return 'AP004';
    }

    public function getName(): string
    {
        return 'Missing Auth on Writes';
    }

    public function evaluate(Endpoint $endpoint): array
    {
        if (!$endpoint->hasWriteMethods()) {
            return [];
        }

        // If there's any auth or explicit anonymous marker, skip
        if ($endpoint->authorization->hasAuth || $endpoint->authorization->hasAllowAnonymous) {
            return [];
        }

        // If there's any middleware at all that might provide auth
        if (!empty($endpoint->authorization->middleware)) {
            return [];
        }

        return [
            new Finding(
                ruleId: $this->getId(),
                ruleName: $this->getName(),
                severity: Severity::Critical,
                message: "Write endpoint '{$endpoint->route}' ({$endpoint->methodsString()}) has no authentication whatsoever.",
                endpoint: $endpoint,
                recommendation: "Add authentication middleware to this write endpoint immediately. Unprotected write endpoints are a critical security risk.",
            ),
        ];
    }
}
