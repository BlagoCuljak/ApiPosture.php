<?php

declare(strict_types=1);

namespace ApiPosture\Rules;

use ApiPosture\Core\Config\Configuration;
use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Finding;

final class RuleEngine
{
    /** @var SecurityRuleInterface[] */
    private array $rules = [];

    public function __construct(
        private readonly Configuration $configuration,
    ) {}

    public function register(SecurityRuleInterface $rule): void
    {
        $this->rules[] = $rule;
    }

    public function registerDefaults(): void
    {
        $this->register(new AP001_PublicWithoutExplicitIntent());
        $this->register(new AP002_AllowAnonymousOnWrite());
        $this->register(new AP003_ControllerActionConflict());
        $this->register(new AP004_MissingAuthOnWrites());
        $this->register(new AP005_ExcessiveRoleAccess());
        $this->register(new AP006_WeakRoleNaming());
        $this->register(new AP007_SensitiveRouteKeywords());
        $this->register(new AP008_UnprotectedEndpoint());
    }

    /**
     * @param Endpoint[] $endpoints
     * @return Finding[]
     */
    public function evaluate(array $endpoints): array
    {
        $findings = [];

        foreach ($this->rules as $rule) {
            if (!$this->configuration->isRuleEnabled($rule->getId())) {
                continue;
            }

            foreach ($endpoints as $endpoint) {
                $ruleFindings = $rule->evaluate($endpoint);

                foreach ($ruleFindings as $finding) {
                    if (!$this->configuration->isSuppressed(
                        $finding->ruleId,
                        $finding->endpoint->route,
                        $finding->endpoint->controllerName,
                    )) {
                        $findings[] = $finding;
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * @return SecurityRuleInterface[]
     */
    public function getRules(): array
    {
        return $this->rules;
    }
}
