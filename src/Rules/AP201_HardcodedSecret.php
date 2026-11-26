<?php

declare(strict_types=1);

namespace ApiPosture\Rules;

use ApiPosture\Core\Model\AuthorizationInfo;
use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\EndpointType;
use ApiPosture\Core\Model\Enums\Severity;
use ApiPosture\Core\Model\Finding;
use ApiPosture\Core\Model\SourceLocation;

/**
 * AP201: Hardcoded secret.
 *
 * A deliberately small, high-precision rule: only credentials with a
 * distinctive vendor-specific format are reported. Generic heuristics
 * (password=, token=, JWTs, connection strings, ...) are intentionally absent.
 * The full secret is never printed.
 */
final class AP201_HardcodedSecret
{
    public const ID = 'AP201';

    /** Directory names (relative to the scanned root) that are never scanned. */
    private const SKIPPED_DIRS = [
        'test', 'tests', 'spec', 'fixtures', 'testdata', 'samples', 'examples',
        'docs', 'vendor', 'node_modules', 'storage',
    ];

    /** Case-insensitive markers that identify a placeholder value. */
    private const PLACEHOLDER_MARKERS = [
        'example', 'xxxx', 'your_', 'your-', '<', '>', '${', '{{',
        'changeme', 'dummy', 'fake', 'sample', 'placeholder', 'redacted',
    ];

    private const MAX_FILE_BYTES = 1048576;

    /** @var array<int, array{0: string, 1: string}> [type, regex] */
    private const PATTERNS = [
        ['AWS access key ID', '/\b(AKIA|ASIA)[0-9A-Z]{16}\b/'],
        ['GCP API key', '/\bAIza[0-9A-Za-z\-_]{35}\b/'],
        ['GitHub token', '/\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b/'],
        ['GitHub fine-grained token', '/\bgithub_pat_[0-9A-Za-z_]{82}\b/'],
        ['GitLab personal access token', '/\bglpat-[0-9A-Za-z\-_]{20,}\b/'],
        ['Stripe live secret key', '/\b(sk|rk)_live_[0-9A-Za-z]{24,}\b/'],
        ['Slack token', '/\bxox[baprs]-[0-9A-Za-z\-]{10,}\b/'],
        ['Slack webhook URL', '#https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9A-Za-z]{24}#'],
        ['SendGrid API key', '/\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b/'],
        ['npm token', '/\bnpm_[0-9A-Za-z]{36}\b/'],
        ['DigitalOcean token', '/\bdop_v1_[0-9a-f]{64}\b/'],
        ['Private key', '/-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/'],
    ];

    public function getId(): string
    {
        return self::ID;
    }

    public function getName(): string
    {
        return 'Hardcoded Secret';
    }

    /**
     * Whether a file (path relative to the scan root) is worth scanning.
     */
    public static function shouldScan(string $relativePath): bool
    {
        $relativePath = strtolower(str_replace('\\', '/', ltrim($relativePath, '/')));
        $segments = explode('/', $relativePath);
        $file = array_pop($segments);

        foreach ($segments as $segment) {
            if (in_array($segment, self::SKIPPED_DIRS, true)) {
                return false;
            }
        }
        if (str_contains($relativePath, 'bootstrap/cache/')) {
            return false;
        }

        if (str_ends_with($file, 'test.php')) {
            return false;
        }
        if (str_starts_with($file, '.env')) {
            // Committed .env files are scanned; templates are not.
            return !preg_match('/\.(example|sample|dist|template|stub)$/', $file);
        }

        return str_ends_with($file, '.php');
    }

    /**
     * Scan file contents. $relativePath is used for reporting and path guards.
     *
     * @return Finding[]
     */
    public function scanContent(string $content, string $relativePath, ?string $absolutePath = null): array
    {
        if (!self::shouldScan($relativePath) || strlen($content) > self::MAX_FILE_BYTES) {
            return [];
        }

        $findings = [];
        $seen = [];
        $lines = preg_split('/\r\n|\r|\n/', $content) ?: [];

        foreach ($lines as $index => $line) {
            if (strlen($line) < 20) {
                continue;
            }
            foreach (self::PATTERNS as [$type, $regex]) {
                if (!preg_match_all($regex, $line, $matches, PREG_OFFSET_CAPTURE)) {
                    continue;
                }
                foreach ($matches[0] as [$value, $offset]) {
                    if (self::isPlaceholder($value)) {
                        continue;
                    }
                    if ($type === 'Private key' && !self::hasKeyBody($lines, $index, $offset + strlen($value))) {
                        continue;
                    }
                    $key = $index . '|' . $type;
                    if (isset($seen[$key])) {
                        continue;
                    }
                    $seen[$key] = true;
                    $findings[] = $this->makeFinding($type, $value, $relativePath, $absolutePath ?? $relativePath, $index + 1);
                }
            }
        }

        return $findings;
    }

    public static function isPlaceholder(string $value): bool
    {
        $lower = strtolower($value);
        foreach (self::PLACEHOLDER_MARKERS as $marker) {
            if (str_contains($lower, $marker)) {
                return true;
            }
        }
        return false;
    }

    /** Never reveal more than the first four characters. */
    public static function redact(string $value): string
    {
        return substr($value, 0, 4) . '…';
    }

    /**
     * A PEM header only counts when base64 key material follows it, so code that
     * merely mentions the header (str_contains, regexes, docs) is not flagged.
     *
     * @param string[] $lines
     */
    private static function hasKeyBody(array $lines, int $lineIndex, int $offset): bool
    {
        $tail = substr($lines[$lineIndex], $offset);
        for ($i = 1; $i <= 3 && strlen($tail) < 200; $i++) {
            $tail .= "\n" . ($lines[$lineIndex + $i] ?? '');
        }
        // Skip separators between header and body: whitespace, quotes, escaped newlines, concatenation.
        $tail = preg_replace('/^(?:\s|\\\\[nr]|["\'.]|\\\\)+/', '', $tail) ?? '';

        return (bool) preg_match('/^[A-Za-z0-9+\/]{16}/', $tail);
    }

    private function makeFinding(string $type, string $value, string $relativePath, string $absolutePath, int $line): Finding
    {
        $location = new SourceLocation($absolutePath, $line);
        $endpoint = new Endpoint(
            route: $relativePath,
            methods: [],
            type: EndpointType::File,
            location: $location,
            authorization: new AuthorizationInfo(),
        );

        return new Finding(
            ruleId: self::ID,
            ruleName: $this->getName(),
            severity: Severity::High,
            message: sprintf('Hardcoded %s (%s) in %s:%d', $type, self::redact($value), $relativePath, $line),
            endpoint: $endpoint,
            recommendation: 'Remove the secret from source control, rotate it, and load it from the environment or a secrets manager.',
        );
    }
}
