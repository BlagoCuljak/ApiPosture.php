<?php

declare(strict_types=1);

namespace ApiPosture\Core\Config;

use ApiPosture\Core\Model\Enums\Severity;

final class Configuration
{
    private Severity $defaultSeverity;
    private Severity $failOnSeverity;
    /** @var array<string, array{route?: string, ruleId?: string, controller?: string}> */
    private array $suppressions;
    /** @var array<string, array{enabled: bool}> */
    private array $rules;
    private bool $useColors;
    private bool $useIcons;

    public function __construct(
        ?Severity $defaultSeverity = null,
        ?Severity $failOnSeverity = null,
        array $suppressions = [],
        array $rules = [],
        bool $useColors = true,
        bool $useIcons = true,
    ) {
        $this->defaultSeverity = $defaultSeverity ?? Severity::Info;
        $this->failOnSeverity = $failOnSeverity ?? Severity::High;
        $this->suppressions = $suppressions;
        $this->rules = $rules;
        $this->useColors = $useColors;
        $this->useIcons = $useIcons;
    }

    public static function load(?string $configPath = null, ?string $scannedPath = null): self
    {
        $configFile = self::resolveConfigFile($configPath, $scannedPath);

        if ($configFile === null) {
            return new self();
        }

        $content = file_get_contents($configFile);
        if ($content === false) {
            return new self();
        }

        $data = json_decode($content, true);
        if (!is_array($data)) {
            return new self();
        }

        return self::fromArray($data);
    }

    public static function fromArray(array $data): self
    {
        $defaultSeverity = null;
        $failOnSeverity = null;

        if (isset($data['severity']['default'])) {
            $defaultSeverity = Severity::fromString($data['severity']['default']);
        }
        if (isset($data['severity']['failOn'])) {
            $failOnSeverity = Severity::fromString($data['severity']['failOn']);
        }

        return new self(
            defaultSeverity: $defaultSeverity,
            failOnSeverity: $failOnSeverity,
            suppressions: $data['suppressions'] ?? [],
            rules: $data['rules'] ?? [],
            useColors: $data['display']['useColors'] ?? true,
            useIcons: $data['display']['useIcons'] ?? true,
        );
    }

    public function getDefaultSeverity(): Severity
    {
        return $this->defaultSeverity;
    }

    public function getFailOnSeverity(): Severity
    {
        return $this->failOnSeverity;
    }

    public function setFailOnSeverity(Severity $severity): void
    {
        $this->failOnSeverity = $severity;
    }

    public function getSuppressions(): array
    {
        return $this->suppressions;
    }

    public function isRuleEnabled(string $ruleId): bool
    {
        if (!isset($this->rules[$ruleId])) {
            return true;
        }
        return $this->rules[$ruleId]['enabled'] ?? true;
    }

    public function useColors(): bool
    {
        return $this->useColors;
    }

    public function setUseColors(bool $useColors): void
    {
        $this->useColors = $useColors;
    }

    public function useIcons(): bool
    {
        return $this->useIcons;
    }

    public function setUseIcons(bool $useIcons): void
    {
        $this->useIcons = $useIcons;
    }

    public function isSuppressed(string $ruleId, string $route, ?string $controller = null): bool
    {
        foreach ($this->suppressions as $suppression) {
            if (isset($suppression['ruleId']) && $suppression['ruleId'] !== $ruleId) {
                continue;
            }
            if (isset($suppression['route']) && !$this->matchesPattern($route, $suppression['route'])) {
                continue;
            }
            if (isset($suppression['controller']) && $controller !== $suppression['controller']) {
                continue;
            }
            return true;
        }
        return false;
    }

    private function matchesPattern(string $value, string $pattern): bool
    {
        if ($pattern === $value) {
            return true;
        }

        // Support wildcard patterns
        $regex = '/^' . str_replace(['\*', '\?'], ['.*', '.'], preg_quote($pattern, '/')) . '$/';
        return (bool) preg_match($regex, $value);
    }

    private static function resolveConfigFile(?string $configPath, ?string $scannedPath): ?string
    {
        if ($configPath !== null && file_exists($configPath)) {
            return $configPath;
        }

        $searchPaths = [];
        if ($scannedPath !== null) {
            $searchPaths[] = rtrim($scannedPath, '/') . '/.apiposture.json';
        }
        $searchPaths[] = getcwd() . '/.apiposture.json';

        foreach ($searchPaths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        return null;
    }
}
