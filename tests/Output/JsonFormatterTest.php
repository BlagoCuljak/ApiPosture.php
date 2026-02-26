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
use ApiPosture\Output\JsonFormatter;
use PHPUnit\Framework\TestCase;

final class JsonFormatterTest extends TestCase
{
    private JsonFormatter $formatter;

    protected function setUp(): void
    {
        $this->formatter = new JsonFormatter();
    }

    public function testOutputsValidJson(): void
    {
        $result = $this->makeScanResult();
        $output = $this->formatter->format($result);

        $decoded = json_decode($output, true);
        $this->assertNotNull($decoded);
        $this->assertIsArray($decoded);
    }

    public function testContainsExpectedStructure(): void
    {
        $result = $this->makeScanResult();
        $output = $this->formatter->format($result);
        $decoded = json_decode($output, true);

        $this->assertArrayHasKey('scannedPath', $decoded);
        $this->assertArrayHasKey('endpoints', $decoded);
        $this->assertArrayHasKey('findings', $decoded);
        $this->assertArrayHasKey('summary', $decoded);
        $this->assertArrayHasKey('duration', $decoded);
    }

    public function testEndpointStructure(): void
    {
        $result = $this->makeScanResult();
        $output = $this->formatter->format($result);
        $decoded = json_decode($output, true);

        $endpoint = $decoded['endpoints'][0];
        $this->assertArrayHasKey('route', $endpoint);
        $this->assertArrayHasKey('methods', $endpoint);
        $this->assertArrayHasKey('classification', $endpoint);
        $this->assertArrayHasKey('authorization', $endpoint);
    }

    public function testFindingStructure(): void
    {
        $result = $this->makeScanResult();
        $output = $this->formatter->format($result);
        $decoded = json_decode($output, true);

        $finding = $decoded['findings'][0];
        $this->assertArrayHasKey('ruleId', $finding);
        $this->assertArrayHasKey('ruleName', $finding);
        $this->assertArrayHasKey('severity', $finding);
        $this->assertArrayHasKey('message', $finding);
        $this->assertArrayHasKey('recommendation', $finding);
    }

    public function testSummaryContainsCounts(): void
    {
        $result = $this->makeScanResult();
        $output = $this->formatter->format($result);
        $decoded = json_decode($output, true);

        $this->assertEquals(1, $decoded['summary']['totalEndpoints']);
        $this->assertEquals(1, $decoded['summary']['totalFindings']);
    }

    public function testEmptyResult(): void
    {
        $result = new ScanResult(
            scannedPath: '/tmp/test',
            endpoints: [],
            findings: [],
        );
        $output = $this->formatter->format($result);
        $decoded = json_decode($output, true);

        $this->assertNotNull($decoded);
        $this->assertEmpty($decoded['endpoints']);
        $this->assertEmpty($decoded['findings']);
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
