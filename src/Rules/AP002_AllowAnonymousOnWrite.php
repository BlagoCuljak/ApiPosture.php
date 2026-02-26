<?php

declare(strict_types=1);

namespace ApiPosture\Rules;

use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\Severity;
use ApiPosture\Core\Model\Finding;

/**
 * AP002: AllowAnonymous/public on write endpoints.
 *
 * Flags write endpoints (POST/PUT/DELETE/PATCH) that are explicitly marked
 * as anonymous/public, with dynamic severity adjustments.
 */
final class AP002_AllowAnonymousOnWrite implements SecurityRuleInterface
{
    private const WEBHOOK_PATTERNS = ['webhook', 'hook', 'callback', 'notify', 'ipn'];
    private const AUTH_PATTERNS = ['login', 'register', 'signup', 'signin', 'token', 'oauth', 'auth', 'password', 'reset', 'forgot'];
    private const ANALYTICS_PATTERNS = ['analytics', 'tracking', 'counter', 'metrics', 'telemetry', 'ping', 'heartbeat'];

    public function getId(): string
    {
        return 'AP002';
    }

    public function getName(): string
    {
        return 'Allow Anonymous on Write';
    }

    public function evaluate(Endpoint $endpoint): array
    {
        if (!$endpoint->hasWriteMethods()) {
            return [];
        }

        if (!$endpoint->authorization->hasAllowAnonymous && $endpoint->authorization->hasAuth) {
            return [];
        }

        $severity = $this->determineSeverity($endpoint);

        return [
            new Finding(
                ruleId: $this->getId(),
                ruleName: $this->getName(),
                severity: $severity,
                message: "Write endpoint '{$endpoint->route}' ({$endpoint->methodsString()}) is publicly accessible.",
                endpoint: $endpoint,
                recommendation: $this->getRecommendation($endpoint, $severity),
            ),
        ];
    }

    private function determineSeverity(Endpoint $endpoint): Severity
    {
        $routeLower = strtolower($endpoint->route);

        // Webhooks: Medium (external services need access)
        foreach (self::WEBHOOK_PATTERNS as $pattern) {
            if (str_contains($routeLower, $pattern)) {
                return Severity::Medium;
            }
        }

        // Auth endpoints: Low (login/register must be public)
        foreach (self::AUTH_PATTERNS as $pattern) {
            if (str_contains($routeLower, $pattern)) {
                return Severity::Low;
            }
        }

        // Analytics/counters: Low
        foreach (self::ANALYTICS_PATTERNS as $pattern) {
            if (str_contains($routeLower, $pattern)) {
                return Severity::Low;
            }
        }

        // Default: High for anonymous writes
        return Severity::High;
    }

    private function getRecommendation(Endpoint $endpoint, Severity $severity): string
    {
        return match ($severity) {
            Severity::Low => "This appears to be an auth/analytics endpoint. Verify this is intentionally public.",
            Severity::Medium => "This appears to be a webhook endpoint. Consider adding signature verification or IP allowlisting.",
            default => "Add authentication to this write endpoint, or explicitly document why it must be public.",
        };
    }
}
