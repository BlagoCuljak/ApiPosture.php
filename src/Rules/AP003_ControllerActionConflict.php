<?php

declare(strict_types=1);

namespace ApiPosture\Rules;

use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\Severity;
use ApiPosture\Core\Model\Finding;

/**
 * AP003: Controller-action authorization conflict.
 *
 * Flags endpoints where the action-level authorization overrides or conflicts
 * with controller-level authorization (e.g., a method skipping inherited auth).
 */
final class AP003_ControllerActionConflict implements SecurityRuleInterface
{
    public function getId(): string
    {
        return 'AP003';
    }

    public function getName(): string
    {
        return 'Controller-Action Auth Conflict';
    }

    public function evaluate(Endpoint $endpoint): array
    {
        // Only applies to controller-based endpoints with inheritance
        if ($endpoint->authorization->inheritedFrom === null) {
            return [];
        }

        // If the controller has auth but the action explicitly allows anonymous
        if ($endpoint->authorization->hasAllowAnonymous && $endpoint->authorization->inheritedFrom === 'controller') {
            return [
                new Finding(
                    ruleId: $this->getId(),
                    ruleName: $this->getName(),
                    severity: Severity::High,
                    message: "Action '{$endpoint->actionName}' on '{$endpoint->controllerName}' overrides controller-level auth with anonymous access.",
                    endpoint: $endpoint,
                    recommendation: "Review whether this action should bypass controller-level authentication. If intentional, document the reason.",
                ),
            ];
        }

        // If class-level has auth but action's effective auth is different (weaker)
        if ($endpoint->authorization->inheritedFrom === 'class'
            && $endpoint->authorization->hasAllowAnonymous) {
            return [
                new Finding(
                    ruleId: $this->getId(),
                    ruleName: $this->getName(),
                    severity: Severity::High,
                    message: "Action '{$endpoint->actionName}' on '{$endpoint->controllerName}' weakens class-level security.",
                    endpoint: $endpoint,
                    recommendation: "Ensure the action-level override is intentional and documented.",
                ),
            ];
        }

        return [];
    }
}
