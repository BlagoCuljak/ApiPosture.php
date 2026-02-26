<?php

declare(strict_types=1);

namespace ApiPosture\Command;

use ApiPosture\Core\Analyzer\ProjectAnalyzer;
use ApiPosture\Core\Config\Configuration;
use ApiPosture\Core\Model\Enums\GroupField;
use ApiPosture\Core\Model\Enums\HttpMethod;
use ApiPosture\Core\Model\Enums\SecurityClassification;
use ApiPosture\Core\Model\Enums\Severity;
use ApiPosture\Core\Model\Enums\SortDirection;
use ApiPosture\Core\Model\Enums\SortField;
use ApiPosture\Output\JsonFormatter;
use ApiPosture\Output\MarkdownFormatter;
use ApiPosture\Output\TerminalFormatter;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class ScanCommand extends Command
{
    protected static $defaultName = 'scan';

    protected function configure(): void
    {
        $this
            ->setName('scan')
            ->setDescription('Scan a PHP project for API security posture issues')
            ->addArgument('path', InputArgument::REQUIRED, 'Path to the project to scan')
            ->addOption('output', 'o', InputOption::VALUE_REQUIRED, 'Output format: terminal, json, markdown', 'terminal')
            ->addOption('output-file', null, InputOption::VALUE_REQUIRED, 'Write output to a file')
            ->addOption('config', 'c', InputOption::VALUE_REQUIRED, 'Path to config file')
            ->addOption('severity', null, InputOption::VALUE_REQUIRED, 'Minimum severity to display: info, low, medium, high, critical')
            ->addOption('fail-on', null, InputOption::VALUE_REQUIRED, 'Fail (exit 1) on findings at or above this severity')
            ->addOption('sort-by', null, InputOption::VALUE_REQUIRED, 'Sort by: severity, route, method, classification, controller, location')
            ->addOption('sort-dir', null, InputOption::VALUE_REQUIRED, 'Sort direction: asc, desc', 'asc')
            ->addOption('classification', null, InputOption::VALUE_REQUIRED, 'Filter by classification: public, authenticated, role_restricted, policy_restricted')
            ->addOption('method', null, InputOption::VALUE_REQUIRED, 'Filter by HTTP method: GET, POST, PUT, DELETE, PATCH')
            ->addOption('route-contains', null, InputOption::VALUE_REQUIRED, 'Filter routes containing this string')
            ->addOption('controller', null, InputOption::VALUE_REQUIRED, 'Filter by controller name')
            ->addOption('rule', null, InputOption::VALUE_REQUIRED, 'Filter findings by rule ID (e.g., AP001)')
            ->addOption('group-by', null, InputOption::VALUE_REQUIRED, 'Group endpoints by: controller, classification, severity, method, type')
            ->addOption('group-findings-by', null, InputOption::VALUE_REQUIRED, 'Group findings by: controller, classification, severity, method, type')
            ->addOption('no-color', null, InputOption::VALUE_NONE, 'Disable colored output')
            ->addOption('no-icons', null, InputOption::VALUE_NONE, 'Disable icon output');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $path = $input->getArgument('path');
        $path = realpath($path);

        if ($path === false || !is_dir($path)) {
            $output->writeln('<error>Invalid path: ' . $input->getArgument('path') . '</error>');
            return Command::FAILURE;
        }

        // Load configuration
        $configPath = $input->getOption('config');
        $config = Configuration::load($configPath, $path);

        // Apply CLI overrides
        if ($input->getOption('fail-on')) {
            $config->setFailOnSeverity(Severity::fromString($input->getOption('fail-on')));
        }
        if ($input->getOption('no-color')) {
            $config->setUseColors(false);
        }
        if ($input->getOption('no-icons')) {
            $config->setUseIcons(false);
        }

        // Run scan
        $analyzer = new ProjectAnalyzer($config);
        $result = $analyzer->scan($path);

        // Apply filters
        $minSeverity = $input->getOption('severity') ? Severity::fromString($input->getOption('severity')) : null;
        $classification = $input->getOption('classification') ? SecurityClassification::from($input->getOption('classification')) : null;
        $method = $input->getOption('method') ? HttpMethod::fromString($input->getOption('method')) : null;
        $routeContains = $input->getOption('route-contains');
        $controller = $input->getOption('controller');
        $ruleId = $input->getOption('rule');

        $filteredEndpoints = ProjectAnalyzer::filterEndpoints(
            $result->endpoints,
            $minSeverity,
            $classification,
            $method,
            $routeContains,
            $controller,
        );

        $filteredFindings = ProjectAnalyzer::filterFindings(
            $result->findings,
            $minSeverity,
            $classification,
            $method,
            $routeContains,
            $controller,
            $ruleId,
        );

        // Apply sorting
        if ($input->getOption('sort-by')) {
            $sortField = SortField::from($input->getOption('sort-by'));
            $sortDir = SortDirection::from($input->getOption('sort-dir'));
            $filteredEndpoints = ProjectAnalyzer::sortEndpoints($filteredEndpoints, $sortField, $sortDir);
            $filteredFindings = ProjectAnalyzer::sortFindings($filteredFindings, $sortField, $sortDir);
        }

        // Build filtered result
        $filteredResult = new \ApiPosture\Core\Model\ScanResult(
            scannedPath: $result->scannedPath,
            endpoints: $filteredEndpoints,
            findings: $filteredFindings,
            scannedFiles: $result->scannedFiles,
            failedFiles: $result->failedFiles,
            duration: $result->duration,
        );

        // Build options for formatters
        $formatOptions = [];
        if ($input->getOption('group-by')) {
            $formatOptions['groupBy'] = GroupField::from($input->getOption('group-by'));
        }
        if ($input->getOption('group-findings-by')) {
            $formatOptions['groupFindingsBy'] = GroupField::from($input->getOption('group-findings-by'));
        }

        // Format output
        $outputFormat = $input->getOption('output');
        $formatted = match ($outputFormat) {
            'json' => (new JsonFormatter())->format($filteredResult, $formatOptions),
            'markdown' => (new MarkdownFormatter())->format($filteredResult, $formatOptions),
            default => null,
        };

        if ($formatted !== null) {
            $outputFile = $input->getOption('output-file');
            if ($outputFile) {
                file_put_contents($outputFile, $formatted);
                $output->writeln("<info>Output written to {$outputFile}</info>");
            } else {
                $output->write($formatted);
            }
        } else {
            // Terminal formatter writes directly to output
            $formatter = new TerminalFormatter(
                useColors: $config->useColors(),
                useIcons: $config->useIcons(),
            );
            $formatter->formatToOutput($output, $filteredResult, $formatOptions);
        }

        // Determine exit code
        $failOnSeverity = $config->getFailOnSeverity();
        foreach ($filteredResult->findings as $finding) {
            if ($finding->severity->value >= $failOnSeverity->value) {
                return Command::FAILURE;
            }
        }

        return Command::SUCCESS;
    }
}
