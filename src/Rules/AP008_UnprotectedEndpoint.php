<?php

declare(strict_types=1);

namespace ApiPosture\Rules;

use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\Severity;
use ApiPosture\Core\Model\Finding;

/**
 * AP008: Unprotected endpoint (no auth middleware at all).
 *
 * Framework-agnostic detection of endpoints with zero auth middleware.
 * Differs from AP004 in that it applies to all HTTP methods, not just writes.
 */
final class AP008_UnprotectedEndpoint implements SecurityRuleInterface
{
    public function getId(): string
    {
        return 'AP008';
    }

    public function getName(): string
    {
        return 'Unprotected Endpoint';
    }

    public function evaluate(Endpoint $endpoint): array
    {
        // If there's any auth, this rule doesn't apply
        if ($endpoint->authorization->hasAuth) {
            return [];
        }

        // If explicitly marked as anonymous/guest, that's intentional
        if ($endpoint->authorization->hasAllowAnonymous) {
            return [];
        }

        // If there's any middleware at all, some protection may exist
        if (!empty($endpoint->authorization->middleware)) {
            return [];
        }

        // Roles or policies present means some form of auth exists
        if (!empty($endpoint->authorization->roles) || !empty($endpoint->authorization->policies)) {
            return [];
        }

        $severity = $endpoint->hasWriteMethods() ? Severity::High : Severity::Info;

        return [
            new Finding(
                ruleId: $this->getId(),
                ruleName: $this->getName(),
                severity: $severity,
                message: "Endpoint '{$endpoint->route}' ({$endpoint->methodsString()}) has no auth middleware.",
                endpoint: $endpoint,
                recommendation: "Add authentication middleware or explicitly mark as public/guest to indicate intentional public access.",
            ),
        ];
    }
}
