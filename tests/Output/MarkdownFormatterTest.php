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
use ApiPosture\Output\MarkdownFormatter;
use PHPUnit\Framework\TestCase;

final class MarkdownFormatterTest extends TestCase
{
    private MarkdownFormatter $formatter;

    protected function setUp(): void
    {
        $this->formatter = new MarkdownFormatter();
    }

    public function testOutputContainsHeader(): void
    {
        $result = $this->makeScanResult();
        $output = $this->formatter->format($result);
        $this->assertStringContainsString('# ApiPosture Scan Results', $output);
    }

    public function testOutputContainsScannedPath(): void
    {
        $result = $this->makeScanResult();
        $output = $this->formatter->format($result);
        $this->assertStringContainsString('/tmp/test', $output);
    }

    public function testOutputContainsEndpointTable(): void
    {
        $result = $this->makeScanResult();
        $output = $this->formatter->format($result);
        $this->assertStringContainsString('## Endpoints', $output);
        $this->assertStringContainsString('| Route |', $output);
        $this->assertStringContainsString('/api/test', $output);
    }

    public function testOutputContainsFindingsDetail(): void
    {
        $result = $this->makeScanResult();
        $output = $this->formatter->format($result);
        $this->assertStringContainsString('## Findings Detail', $output);
        $this->assertStringContainsString('AP001', $output);
        $this->assertStringContainsString('Test message', $output);
    }

    public function testOutputContainsSeveritySummary(): void
    {
        $result = $this->makeScanResult();
        $output = $this->formatter->format($result);
        $this->assertStringContainsString('## Findings Summary', $output);
        $this->assertStringContainsString('Medium', $output);
    }

    public function testEmptyResult(): void
    {
        $result = new ScanResult(
            scannedPath: '/tmp/test',
            endpoints: [],
            findings: [],
        );
        $output = $this->formatter->format($result);
        $this->assertStringContainsString('# ApiPosture Scan Results', $output);
        $this->assertStringNotContainsString('## Endpoints', $output);
        $this->assertStringNotContainsString('## Findings', $output);
    }

    private function makeScanResult(): ScanResult
    {
        $endpoint = new Endpoint(
            route: '/api/test',
            methods: [HttpMethod::GET],
            type: EndpointType::Route,
            location: new SourceLocation('test.php', 1),
            authorization: new AuthorizationInfo(),
            classification: SecurityClassification::Public,
        );

        $finding = new Finding(
            ruleId: 'AP001',
            ruleName: 'Test Rule',
            severity: Severity::Medium,
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
