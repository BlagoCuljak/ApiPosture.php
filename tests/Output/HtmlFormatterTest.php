<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Output;

use ApiPosture\Core\Model\AuthorizationInfo;
use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\EndpointType;
use ApiPosture\Core\Model\Enums\HttpMethod;
use ApiPosture\Core\Model\Enums\SecurityClassification;
use ApiPosture\Core\Model\Enums\Severity;
use ApiPosture\Core\Model\Finding;
use ApiPosture\Core\Model\ScanResult;
use ApiPosture\Core\Model\SourceLocation;
use ApiPosture\Output\HtmlFormatter;
use PHPUnit\Framework\TestCase;

final class HtmlFormatterTest extends TestCase
{
    private HtmlFormatter $formatter;

    protected function setUp(): void
    {
        $this->formatter = new HtmlFormatter();
    }

    public function testRendersFindingsWithSeverityClass(): void
    {
        $output = $this->formatter->format($this->makeScanResult(Severity::Medium));

        $this->assertStringContainsString('<div class="finding medium">', $output);
        $this->assertStringContainsString('severity-medium', $output);
        $this->assertStringContainsString('AP001', $output);
        $this->assertStringContainsString('Test message', $output);
        $this->assertStringContainsString('/api/test', $output);
    }

    public function testRendersEverySeverity(): void
    {
        foreach (Severity::cases() as $severity) {
            $output = $this->formatter->format($this->makeScanResult($severity));
            $this->assertStringContainsString(
                '<div class="finding ' . strtolower($severity->name) . '">',
                $output,
            );
        }
    }

    public function testEscapesUserControlledValues(): void
    {
        $output = $this->formatter->format($this->makeScanResult(Severity::High, '/api/<script>'));

        $this->assertStringNotContainsString('<script>', $output);
        $this->assertStringContainsString('/api/&lt;script&gt;', $output);
    }

    public function testEmptyResult(): void
    {
        $output = $this->formatter->format(new ScanResult(
            scannedPath: '/tmp/test',
            endpoints: [],
            findings: [],
        ));

        $this->assertStringContainsString('ApiPosture Security Scan Report', $output);
        $this->assertStringNotContainsString('class="finding ', $output);
    }

    private function makeScanResult(Severity $severity, string $route = '/api/test'): ScanResult
    {
        $endpoint = new Endpoint(
            route: $route,
            methods: [HttpMethod::GET],
            type: EndpointType::Route,
            location: new SourceLocation('test.php', 1),
            authorization: new AuthorizationInfo(),
            classification: SecurityClassification::Public,
        );

        $finding = new Finding(
            ruleId: 'AP001',
            ruleName: 'Test Rule',
            severity: $severity,
            message: 'Test message',
            endpoint: $endpoint,
            recommendation: 'Test recommendation',
        );

        return new ScanResult(
            scannedPath: '/tmp/test',
            endpoints: [$endpoint],
            findings: [$finding],
            scannedFiles: ['test.php'],
            duration: 0.5,
        );
    }
}
