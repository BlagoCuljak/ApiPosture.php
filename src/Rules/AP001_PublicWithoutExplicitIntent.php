<?php

declare(strict_types=1);

namespace ApiPosture\Rules;

use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\SecurityClassification;
use ApiPosture\Core\Model\Enums\Severity;
use ApiPosture\Core\Model\Finding;

/**
 * AP001: Public endpoint without explicit anonymous/guest intent.
 *
 * Flags endpoints that are publicly accessible but lack an explicit marker
 * (e.g., AllowAnonymous, guest middleware) indicating this is intentional.
 */
final class AP001_PublicWithoutExplicitIntent implements SecurityRuleInterface
{
    public function getId(): string
    {
        return 'AP001';
    }

    public function getName(): string
    {
        return 'Public Without Explicit Intent';
    }

    public function evaluate(Endpoint $endpoint): array
    {
        if ($endpoint->classification !== SecurityClassification::Public) {
            return [];
        }

        // If explicitly marked as anonymous/guest, that's fine
        if ($endpoint->authorization->hasAllowAnonymous) {
            return [];
        }

        // If there's auth, not public
        if ($endpoint->authorization->hasAuth) {
            return [];
        }

        return [
            new Finding(
                ruleId: $this->getId(),
                ruleName: $this->getName(),
                severity: Severity::Medium,
                message: "Endpoint '{$endpoint->route}' is publicly accessible without explicit anonymous intent.",
                endpoint: $endpoint,
                recommendation: "Add explicit guest/AllowAnonymous middleware to confirm this endpoint is intentionally public, or add authentication.",
            ),
        ];
    }
}
