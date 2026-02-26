<?php

declare(strict_types=1);

namespace ApiPosture\Rules;

use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\Severity;
use ApiPosture\Core\Model\Finding;

/**
 * AP006: Weak/generic role naming.
 *
 * Flags endpoints using generic role names that provide little security value.
 */
final class AP006_WeakRoleNaming implements SecurityRuleInterface
{
    private const WEAK_ROLES = [
        'user', 'admin', 'guest', 'member', 'manager', 'superuser',
        'super_admin', 'superadmin', 'root', 'default', 'basic',
        'ROLE_USER', 'ROLE_ADMIN',
    ];

    public function getId(): string
    {
        return 'AP006';
    }

    public function getName(): string
    {
        return 'Weak Role Naming';
    }

    public function evaluate(Endpoint $endpoint): array
    {
        if (empty($endpoint->authorization->roles)) {
            return [];
        }

        $weakRoles = [];
        foreach ($endpoint->authorization->roles as $role) {
            $normalized = strtolower(str_replace(['ROLE_', '-', '_'], ['', '', ''], $role));
            foreach (self::WEAK_ROLES as $weak) {
                $weakNormalized = strtolower(str_replace(['ROLE_', '-', '_'], ['', '', ''], $weak));
                if ($normalized === $weakNormalized) {
                    $weakRoles[] = $role;
                    break;
                }
            }
        }

        if (empty($weakRoles)) {
            return [];
        }

        $roleList = implode(', ', $weakRoles);

        return [
            new Finding(
                ruleId: $this->getId(),
                ruleName: $this->getName(),
                severity: Severity::Low,
                message: "Endpoint '{$endpoint->route}' uses generic role names: {$roleList}.",
                endpoint: $endpoint,
                recommendation: "Use more specific, descriptive role names that reflect actual business permissions (e.g., 'invoice_manager' instead of 'admin').",
            ),
        ];
    }
}
