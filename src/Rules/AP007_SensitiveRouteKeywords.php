<?php

declare(strict_types=1);

namespace ApiPosture\Rules;

use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\Severity;
use ApiPosture\Core\Model\Finding;

/**
 * AP007: Sensitive keywords in route paths.
 *
 * Flags routes containing keywords that suggest sensitive operations,
 * especially when combined with insufficient auth.
 */
final class AP007_SensitiveRouteKeywords implements SecurityRuleInterface
{
    private const SENSITIVE_KEYWORDS = [
        'admin', 'debug', 'export', 'internal', 'secret',
        'config', 'configuration', 'settings', 'system',
        'manage', 'management', 'dashboard', 'panel',
        'backup', 'dump', 'migrate', 'seed',
        'impersonate', 'sudo', 'elevate',
        'private', 'restricted', 'confidential',
    ];

    public function getId(): string
    {
        return 'AP007';
    }

    public function getName(): string
    {
        return 'Sensitive Route Keywords';
    }

    public function evaluate(Endpoint $endpoint): array
    {
        $routeLower = strtolower($endpoint->route);
        $foundKeywords = [];

        // Split route into word-level tokens to avoid substring false positives
        // e.g. 'manage' must NOT match 'object-manager', 'panel' must NOT match 'expand'
        $tokens = preg_split('/[\/\-_\.]+/', $routeLower, -1, PREG_SPLIT_NO_EMPTY) ?: [];

        foreach (self::SENSITIVE_KEYWORDS as $keyword) {
            if (in_array($keyword, $tokens, true)) {
                $foundKeywords[] = $keyword;
            }
        }

        if (empty($foundKeywords)) {
            return [];
        }

        // Higher severity if no auth
        $severity = $endpoint->authorization->hasAuth ? Severity::Low : Severity::High;
        $keywordList = implode(', ', $foundKeywords);

        return [
            new Finding(
                ruleId: $this->getId(),
                ruleName: $this->getName(),
                severity: $severity,
                message: "Route '{$endpoint->route}' contains sensitive keywords: {$keywordList}.",
                endpoint: $endpoint,
                recommendation: $endpoint->authorization->hasAuth
                    ? "Ensure the authorization level matches the sensitivity implied by the route keywords."
                    : "This route contains sensitive keywords but has no authentication. Add appropriate auth controls.",
            ),
        ];
    }
}
