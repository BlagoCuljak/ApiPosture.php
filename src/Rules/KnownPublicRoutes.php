<?php

declare(strict_types=1);

namespace ApiPosture\Rules;

/**
 * Shared helper identifying routes that are public by convention.
 *
 * Auth entry points, OAuth2/token flows, password-reset flows, and
 * infrastructure probes must be accessible without prior authentication.
 * Any rule that would flag "no auth" should skip these routes.
 */
final class KnownPublicRoutes
{
    /**
     * Individual path-segment words that indicate a public endpoint.
     * Each entry is matched as a whole word after splitting a segment on '-' and '_'.
     */
    private const SEGMENTS = [
        // Auth entry points
        'login', 'logout', 'signin', 'signout', 'signup', 'register',
        // OAuth2 / token flows
        'token', 'authorize', 'oauth', 'refresh', 'grant', 'callback',
        // Password / account flows
        'forgot', 'verify', 'confirm', 'activate', 'unsubscribe', 'resend',
        // 2FA / MFA
        '2fa', 'totp', 'mfa', 'webauthn',
        // Federation
        'sso', 'saml',
        // Infrastructure probes
        'health', 'healthz', 'liveness', 'readiness', 'ping',
        // Public contact
        'contact',
    ];

    /**
     * Full hyphenated segment names matched as-is before word-splitting.
     * Use this for compounds where the individual parts would be too generic.
     */
    private const COMPOUND_SEGMENTS = [
        'check-email', 'reset-password', 'forgot-password', 'verify-email',
        'change-password', 'confirm-email', 'resend-verification', 'magic-link',
    ];

    /**
     * Full underscore-joined segment names matched as-is (common in OAuth2 routes).
     */
    private const UNDERSCORE_SEGMENTS = [
        'access_token', 'device_authorization',
    ];

    public static function isKnownPublicEndpoint(string $route): bool
    {
        $lower = strtolower($route);

        // Split on '/' to get individual path segments
        $pathSegments = array_filter(explode('/', $lower), fn (string $s) => $s !== '');

        foreach ($pathSegments as $seg) {
            // Skip dynamic parameters: {id}, {id:type}, :param
            if (str_starts_with($seg, '{') || str_starts_with($seg, ':')) {
                continue;
            }

            // Strip trailing file extensions (.php, .html, etc.)
            $seg = (string) preg_replace('/\.\w+$/', '', $seg);

            // Direct match for underscore compounds (access_token, device_authorization)
            if (in_array($seg, self::UNDERSCORE_SEGMENTS, true)) {
                return true;
            }

            // Direct match for hyphen compounds (check-email, reset-password, …)
            if (in_array($seg, self::COMPOUND_SEGMENTS, true)) {
                return true;
            }

            // Word-level match: split segment on '-' and '_', check each part
            $parts = preg_split('/[-_]/', $seg, -1, PREG_SPLIT_NO_EMPTY);
            if ($parts !== false) {
                foreach ($parts as $part) {
                    if (in_array($part, self::SEGMENTS, true)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
