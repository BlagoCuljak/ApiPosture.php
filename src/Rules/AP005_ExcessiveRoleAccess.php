<?php

declare(strict_types=1);

namespace ApiPosture\Rules;

use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\Severity;
use ApiPosture\Core\Model\Finding;

/**
 * AP005: Excessive role access.
 *
 * Flags endpoints with more than 3 roles, suggesting overly broad access
 * or a need for better role hierarchy.
 */
final class AP005_ExcessiveRoleAccess implements SecurityRuleInterface
{
    private const MAX_ROLES = 3;

    public function getId(): string
    {
        return 'AP005';
    }

    public function getName(): string
    {
        return 'Excessive Role Access';
    }

    public function evaluate(Endpoint $endpoint): array
    {
        $roleCount = count($endpoint->authorization->roles);

        if ($roleCount <= self::MAX_ROLES) {
            return [];
        }

        return [
            new Finding(
                ruleId: $this->getId(),
                ruleName: $this->getName(),
                severity: Severity::Medium,
                message: "Endpoint '{$endpoint->route}' has {$roleCount} roles assigned (threshold: " . self::MAX_ROLES . ").",
                endpoint: $endpoint,
                recommendation: "Consider consolidating roles or creating a role hierarchy. Too many roles on one endpoint may indicate overly broad access.",
            ),
        ];
    }
}
