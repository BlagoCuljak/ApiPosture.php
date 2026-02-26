<?php

declare(strict_types=1);

namespace ApiPosture\Output;

use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Finding;
use ApiPosture\Core\Model\ScanResult;
use ApiPosture\Core\Model\Enums\GroupField;
use ApiPosture\Core\Model\Enums\Severity;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\OutputInterface;

final class TerminalFormatter implements OutputFormatterInterface
{
    public function __construct(
        private readonly bool $useColors = true,
        private readonly bool $useIcons = true,
    ) {}

    public function format(ScanResult $result, array $options = []): string
    {
        $buffer = new BufferedOutput();
        if (!$this->useColors) {
            $buffer->setDecorated(false);
        }

        $this->renderHeader($buffer, $result);
        $this->renderSummary($buffer, $result);

        if (!empty($result->endpoints)) {
            $this->renderEndpoints($buffer, $result, $options);
        }

        if (!empty($result->findings)) {
            $this->renderFindings($buffer, $result, $options);
        }

        if (!empty($result->failedFiles)) {
            $this->renderFailedFiles($buffer, $result);
        }

        return $buffer->fetch();
    }

    public function formatToOutput(OutputInterface $output, ScanResult $result, array $options = []): void
    {
        $this->renderHeader($output, $result);
        $this->renderSummary($output, $result);

        if (!empty($result->endpoints)) {
            $this->renderEndpoints($output, $result, $options);
        }

        if (!empty($result->findings)) {
            $this->renderFindings($output, $result, $options);
        }

        if (!empty($result->failedFiles)) {
            $this->renderFailedFiles($output, $result);
        }
    }

    private function renderHeader(OutputInterface $output, ScanResult $result): void
    {
        $icon = $this->useIcons ? '🔍 ' : '';
        $output->writeln('');
        $output->writeln("{$icon}<info>ApiPosture Scan Results</info>");
        $output->writeln(str_repeat('─', 60));
        $output->writeln("  Path:     {$result->scannedPath}");
        $output->writeln(sprintf("  Duration: %.2fs", $result->duration));
        $output->writeln("  Files:    " . count($result->scannedFiles) . " scanned");
        $output->writeln('');
    }

    private function renderSummary(OutputInterface $output, ScanResult $result): void
    {
        $endpointIcon = $this->useIcons ? '📊 ' : '';
        $output->writeln("{$endpointIcon}<info>Summary</info>");

        $table = new Table($output);
        $table->setHeaders(['Metric', 'Count']);
        $table->addRow(['Endpoints', (string) count($result->endpoints)]);
        $table->addRow(['Findings', (string) count($result->findings)]);

        // Severity breakdown
        foreach (Severity::cases() as $severity) {
            $count = count(array_filter($result->findings, fn(Finding $f) => $f->severity === $severity));
            if ($count > 0) {
                $label = $this->severityLabel($severity);
                $table->addRow(["  {$label}", (string) $count]);
            }
        }

        $table->render();
        $output->writeln('');
    }

    private function renderEndpoints(OutputInterface $output, ScanResult $result, array $options): void
    {
        $icon = $this->useIcons ? '🌐 ' : '';
        $output->writeln("{$icon}<info>Endpoints</info>");

        $groupBy = $options['groupBy'] ?? null;
        if ($groupBy !== null) {
            $this->renderGroupedEndpoints($output, $result->endpoints, $groupBy);
        } else {
            $this->renderEndpointTable($output, $result->endpoints);
        }

        $output->writeln('');
    }

    private function renderEndpointTable(OutputInterface $output, array $endpoints): void
    {
        $table = new Table($output);
        $table->setHeaders(['Route', 'Methods', 'Classification', 'Controller', 'Auth']);

        foreach ($endpoints as $endpoint) {
            $table->addRow([
                $endpoint->route,
                $endpoint->methodsString(),
                $endpoint->classification->label(),
                $endpoint->controllerName ?? '-',
                $endpoint->authorization->hasAuth ? '<info>Yes</info>' : '<comment>No</comment>',
            ]);
        }

        $table->render();
    }

    /**
     * @param Endpoint[] $endpoints
     */
    private function renderGroupedEndpoints(OutputInterface $output, array $endpoints, GroupField $groupBy): void
    {
        $groups = $this->groupEndpoints($endpoints, $groupBy);

        foreach ($groups as $groupName => $groupEndpoints) {
            $output->writeln("  <comment>{$groupName}</comment>");
            $this->renderEndpointTable($output, $groupEndpoints);
            $output->writeln('');
        }
    }

    private function renderFindings(OutputInterface $output, ScanResult $result, array $options): void
    {
        $icon = $this->useIcons ? '⚠️  ' : '';
        $output->writeln("{$icon}<info>Findings</info>");

        $groupFindingsBy = $options['groupFindingsBy'] ?? null;
        if ($groupFindingsBy !== null) {
            $groups = $this->groupFindings($result->findings, $groupFindingsBy);
            foreach ($groups as $groupName => $findings) {
                $output->writeln("  <comment>{$groupName}</comment>");
                $this->renderFindingsList($output, $findings);
                $output->writeln('');
            }
        } else {
            $this->renderFindingsList($output, $result->findings);
        }

        $output->writeln('');
    }

    /**
     * @param Finding[] $findings
     */
    private function renderFindingsList(OutputInterface $output, array $findings): void
    {
        foreach ($findings as $finding) {
            $severityLabel = $this->severityLabel($finding->severity);
            $output->writeln("  [{$finding->ruleId}] {$severityLabel} {$finding->ruleName}");
            $output->writeln("    Route: {$finding->endpoint->route}");
            $output->writeln("    {$finding->message}");
            if (!empty($finding->recommendation)) {
                $output->writeln("    <comment>→ {$finding->recommendation}</comment>");
            }
            $output->writeln('');
        }
    }

    private function renderFailedFiles(OutputInterface $output, ScanResult $result): void
    {
        $icon = $this->useIcons ? '❌ ' : '';
        $output->writeln("{$icon}<error>Failed Files</error>");
        foreach ($result->failedFiles as $file) {
            $output->writeln("  - {$file}");
        }
        $output->writeln('');
    }

    private function severityLabel(Severity $severity): string
    {
        $icon = $this->useIcons ? match ($severity) {
            Severity::Critical => '🔴',
            Severity::High => '🟠',
            Severity::Medium => '🟡',
            Severity::Low => '🔵',
            Severity::Info => 'ℹ️',
        } . ' ' : '';

        $colorTag = match ($severity) {
            Severity::Critical => 'error',
            Severity::High => 'error',
            Severity::Medium => 'comment',
            Severity::Low => 'info',
            Severity::Info => 'info',
        };

        return "{$icon}<{$colorTag}>{$severity->label()}</{$colorTag}>";
    }

    /**
     * @param Endpoint[] $endpoints
     * @return array<string, Endpoint[]>
     */
    private function groupEndpoints(array $endpoints, GroupField $groupBy): array
    {
        $groups = [];
        foreach ($endpoints as $endpoint) {
            $key = match ($groupBy) {
                GroupField::Controller => $endpoint->controllerName ?? 'No Controller',
                GroupField::Classification => $endpoint->classification->label(),
                GroupField::Method => $endpoint->methodsString(),
                GroupField::Type => $endpoint->type->value,
                GroupField::Severity => 'N/A',
            };
            $groups[$key][] = $endpoint;
        }
        ksort($groups);
        return $groups;
    }

    /**
     * @param Finding[] $findings
     * @return array<string, Finding[]>
     */
    private function groupFindings(array $findings, GroupField $groupBy): array
    {
        $groups = [];
        foreach ($findings as $finding) {
            $key = match ($groupBy) {
                GroupField::Controller => $finding->endpoint->controllerName ?? 'No Controller',
                GroupField::Classification => $finding->endpoint->classification->label(),
                GroupField::Severity => $finding->severity->label(),
                GroupField::Method => $finding->endpoint->methodsString(),
                GroupField::Type => $finding->endpoint->type->value,
            };
            $groups[$key][] = $finding;
        }
        ksort($groups);
        return $groups;
    }
}
