<?php

declare(strict_types=1);

namespace ApiPosture\Core\Classification;

use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\SecurityClassification;

final class SecurityClassifier
{
    /**
     * @param Endpoint[] $endpoints
     * @return Endpoint[]
     */
    public function classifyAll(array $endpoints): array
    {
        foreach ($endpoints as $endpoint) {
            $endpoint->classification = $this->classify($endpoint);
        }
        return $endpoints;
    }

    public function classify(Endpoint $endpoint): SecurityClassification
    {
        $auth = $endpoint->authorization;

        if ($auth->hasAllowAnonymous || (!$auth->hasAuth && empty($auth->roles) && empty($auth->policies))) {
            return SecurityClassification::Public;
        }

        if (!empty($auth->policies)) {
            return SecurityClassification::PolicyRestricted;
        }

        if (!empty($auth->roles)) {
            return SecurityClassification::RoleRestricted;
        }

        if ($auth->hasAuth) {
            return SecurityClassification::Authenticated;
        }

        return SecurityClassification::Public;
    }
}
