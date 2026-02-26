<?php

declare(strict_types=1);

namespace ApiPosture\Core\Analyzer;

use ApiPosture\Core\Classification\SecurityClassifier;
use ApiPosture\Core\Config\Configuration;
use ApiPosture\Core\Discovery\EndpointDiscovererInterface;
use ApiPosture\Core\Discovery\LaravelEndpointDiscoverer;
use ApiPosture\Core\Discovery\PlainPhpEndpointDiscoverer;
use ApiPosture\Core\Discovery\SlimEndpointDiscoverer;
use ApiPosture\Core\Discovery\SymfonyEndpointDiscoverer;
use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\GroupField;
use ApiPosture\Core\Model\Enums\HttpMethod;
use ApiPosture\Core\Model\Enums\SecurityClassification;
use ApiPosture\Core\Model\Enums\Severity;
use ApiPosture\Core\Model\Enums\SortDirection;
use ApiPosture\Core\Model\Enums\SortField;
use ApiPosture\Core\Model\Finding;
use ApiPosture\Core\Model\ScanResult;
use ApiPosture\Rules\RuleEngine;
use PhpParser\ParserFactory;
use PhpParser\Parser;
use Symfony\Component\Finder\Finder;

final class ProjectAnalyzer
{
    private Parser $parser;
    /** @var EndpointDiscovererInterface[] */
    private array $discoverers;
    private SecurityClassifier $classifier;
    private RuleEngine $ruleEngine;

    public function __construct(
        private readonly Configuration $configuration,
    ) {
        $this->parser = (new ParserFactory())->createForNewestSupportedVersion();
        $this->discoverers = [
            new LaravelEndpointDiscoverer(),
            new SymfonyEndpointDiscoverer(),
            new SlimEndpointDiscoverer(),
            new PlainPhpEndpointDiscoverer(),
        ];
        $this->classifier = new SecurityClassifier();
        $this->ruleEngine = new RuleEngine($configuration);
        $this->ruleEngine->registerDefaults();
    }

    public function scan(string $path): ScanResult
    {
        $startTime = microtime(true);

        // 1. Discover PHP files
        $phpFiles = $this->findPhpFiles($path);

        $allEndpoints = [];
        $scannedFiles = [];
        $failedFiles = [];

        // 2. Parse each file and run discoverers
        foreach ($phpFiles as $file) {
            $filePath = $file->getRealPath();
            if ($filePath === false) {
                continue;
            }

            $scannedFiles[] = $filePath;

            try {
                $ast = $this->parser->parse(file_get_contents($filePath));
                if ($ast === null) {
                    continue;
                }

                foreach ($this->discoverers as $discoverer) {
                    if ($discoverer->supports($ast, $filePath)) {
                        $endpoints = $discoverer->discover($ast, $filePath);
                        $allEndpoints = array_merge($allEndpoints, $endpoints);
                    }
                }
            } catch (\Throwable) {
                $failedFiles[] = $filePath;
            }
        }

        // 3. Classify all endpoints
        $allEndpoints = $this->classifier->classifyAll($allEndpoints);

        // 4. Run rule engine
        $findings = $this->ruleEngine->evaluate($allEndpoints);

        $duration = microtime(true) - $startTime;

        return new ScanResult(
            scannedPath: $path,
            endpoints: $allEndpoints,
            findings: $findings,
            scannedFiles: $scannedFiles,
            failedFiles: $failedFiles,
            duration: $duration,
        );
    }

    /**
     * @return \Symfony\Component\Finder\Finder
     */
    private function findPhpFiles(string $path): Finder
    {
        $finder = new Finder();
        $finder->files()
            ->in($path)
            ->name('*.php')
            ->notPath('vendor')
            ->notPath('node_modules')
            ->notPath('.git')
            ->sortByName();

        return $finder;
    }

    /**
     * Sort endpoints by the given field and direction.
     *
     * @param Endpoint[] $endpoints
     * @return Endpoint[]
     */
    public static function sortEndpoints(array $endpoints, SortField $field, SortDirection $direction = SortDirection::Ascending): array
    {
        usort($endpoints, function (Endpoint $a, Endpoint $b) use ($field, $direction) {
            $cmp = match ($field) {
                SortField::Route => strcmp($a->route, $b->route),
                SortField::Method => strcmp($a->methodsString(), $b->methodsString()),
                SortField::Classification => strcmp($a->classification->value, $b->classification->value),
                SortField::Controller => strcmp($a->controllerName ?? '', $b->controllerName ?? ''),
                SortField::Location => strcmp((string) $a->location, (string) $b->location),
                SortField::Severity => 0, // Endpoints don't have severity
            };

            return $direction === SortDirection::Descending ? -$cmp : $cmp;
        });

        return $endpoints;
    }

    /**
     * Sort findings by the given field and direction.
     *
     * @param Finding[] $findings
     * @return Finding[]
     */
    public static function sortFindings(array $findings, SortField $field, SortDirection $direction = SortDirection::Ascending): array
    {
        usort($findings, function (Finding $a, Finding $b) use ($field, $direction) {
            $cmp = match ($field) {
                SortField::Severity => $a->severity->value <=> $b->severity->value,
                SortField::Route => strcmp($a->endpoint->route, $b->endpoint->route),
                SortField::Method => strcmp($a->endpoint->methodsString(), $b->endpoint->methodsString()),
                SortField::Classification => strcmp($a->endpoint->classification->value, $b->endpoint->classification->value),
                SortField::Controller => strcmp($a->endpoint->controllerName ?? '', $b->endpoint->controllerName ?? ''),
                SortField::Location => strcmp((string) $a->endpoint->location, (string) $b->endpoint->location),
            };

            return $direction === SortDirection::Descending ? -$cmp : $cmp;
        });

        return $findings;
    }

    /**
     * Filter endpoints by given criteria.
     *
     * @param Endpoint[] $endpoints
     * @return Endpoint[]
     */
    public static function filterEndpoints(
        array $endpoints,
        ?Severity $minSeverity = null,
        ?SecurityClassification $classification = null,
        ?HttpMethod $method = null,
        ?string $routeContains = null,
        ?string $controller = null,
    ): array {
        return array_values(array_filter($endpoints, function (Endpoint $endpoint) use ($classification, $method, $routeContains, $controller) {
            if ($classification !== null && $endpoint->classification !== $classification) {
                return false;
            }
            if ($method !== null && !in_array($method, $endpoint->methods, true)) {
                return false;
            }
            if ($routeContains !== null && !str_contains(strtolower($endpoint->route), strtolower($routeContains))) {
                return false;
            }
            if ($controller !== null && $endpoint->controllerName !== $controller) {
                return false;
            }
            return true;
        }));
    }

    /**
     * Filter findings by given criteria.
     *
     * @param Finding[] $findings
     * @return Finding[]
     */
    public static function filterFindings(
        array $findings,
        ?Severity $minSeverity = null,
        ?SecurityClassification $classification = null,
        ?HttpMethod $method = null,
        ?string $routeContains = null,
        ?string $controller = null,
        ?string $ruleId = null,
    ): array {
        return array_values(array_filter($findings, function (Finding $finding) use ($minSeverity, $classification, $method, $routeContains, $controller, $ruleId) {
            if ($minSeverity !== null && $finding->severity->value < $minSeverity->value) {
                return false;
            }
            if ($classification !== null && $finding->endpoint->classification !== $classification) {
                return false;
            }
            if ($method !== null && !in_array($method, $finding->endpoint->methods, true)) {
                return false;
            }
            if ($routeContains !== null && !str_contains(strtolower($finding->endpoint->route), strtolower($routeContains))) {
                return false;
            }
            if ($controller !== null && $finding->endpoint->controllerName !== $controller) {
                return false;
            }
            if ($ruleId !== null && $finding->ruleId !== $ruleId) {
                return false;
            }
            return true;
        }));
    }
}
