<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Command;

use ApiPosture\Command\ScanCommand;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

final class ScanCommandTest extends TestCase
{
    private CommandTester $commandTester;

    protected function setUp(): void
    {
        $application = new Application();
        $application->add(new ScanCommand());
        $command = $application->find('scan');
        $this->commandTester = new CommandTester($command);
    }

    public function testScanLaravelFixtures(): void
    {
        $this->commandTester->execute([
            'path' => __DIR__ . '/../Fixtures/Laravel',
            '--output' => 'json',
        ]);

        $output = $this->commandTester->getDisplay();
        $decoded = json_decode($output, true);

        $this->assertNotNull($decoded, "Output should be valid JSON: {$output}");
        $this->assertArrayHasKey('endpoints', $decoded);
        $this->assertArrayHasKey('findings', $decoded);
        $this->assertNotEmpty($decoded['endpoints'], 'Should find Laravel endpoints');
    }

    public function testScanLaravelGroupedRoutesAndIgnoresTestHarness(): void
    {
        $this->commandTester->execute([
            'path' => __DIR__ . '/../Fixtures/LaravelGroups',
            '--output' => 'json',
        ]);

        $decoded = json_decode($this->commandTester->getDisplay(), true);
        $this->assertNotNull($decoded);

        $routes = [];
        foreach ($decoded['endpoints'] as $endpoint) {
            $routes[implode(',', $endpoint['methods']) . ' ' . $endpoint['route']] = $endpoint['authorization']['hasAuth'];
        }
        ksort($routes);

        $this->assertSame([
            'GET /health-check' => false,
            'GET /professional/delete/{hardDelete}' => false,
            'POST /login' => false,
            'POST /reset-password' => false,
            'POST /signup' => false,
            'PUT /auth/profile' => true,
        ], $routes);
    }

    public function testScanSymfonyFixtures(): void
    {
        $this->commandTester->execute([
            'path' => __DIR__ . '/../Fixtures/Symfony',
            '--output' => 'json',
        ]);

        $output = $this->commandTester->getDisplay();
        $decoded = json_decode($output, true);

        $this->assertNotNull($decoded, "Output should be valid JSON: {$output}");
        $this->assertNotEmpty($decoded['endpoints'], 'Should find Symfony endpoints');
    }

    public function testScanSlimFixtures(): void
    {
        $this->commandTester->execute([
            'path' => __DIR__ . '/../Fixtures/Slim',
            '--output' => 'json',
        ]);

        $output = $this->commandTester->getDisplay();
        $decoded = json_decode($output, true);

        $this->assertNotNull($decoded, "Output should be valid JSON: {$output}");
        $this->assertNotEmpty($decoded['endpoints'], 'Should find Slim endpoints');
    }

    public function testJsonOutput(): void
    {
        $this->commandTester->execute([
            'path' => __DIR__ . '/../Fixtures/Laravel',
            '--output' => 'json',
        ]);

        $output = $this->commandTester->getDisplay();
        $decoded = json_decode($output, true);
        $this->assertNotNull($decoded);
    }

    public function testMarkdownOutput(): void
    {
        $this->commandTester->execute([
            'path' => __DIR__ . '/../Fixtures/Laravel',
            '--output' => 'markdown',
        ]);

        $output = $this->commandTester->getDisplay();
        $this->assertStringContainsString('# ApiPosture Scan Results', $output);
    }

    public function testTerminalOutput(): void
    {
        $this->commandTester->execute([
            'path' => __DIR__ . '/../Fixtures/Laravel',
            '--output' => 'terminal',
        ]);

        $output = $this->commandTester->getDisplay();
        $this->assertStringContainsString('ApiPosture Scan Results', $output);
    }

    public function testInvalidPath(): void
    {
        $this->commandTester->execute([
            'path' => '/nonexistent/path',
        ]);

        $this->assertEquals(1, $this->commandTester->getStatusCode());
    }

    public function testFailOnSeverity(): void
    {
        $this->commandTester->execute([
            'path' => __DIR__ . '/../Fixtures/Laravel',
            '--output' => 'json',
            '--fail-on' => 'info',
        ]);

        // Should fail since there will be findings at Info level or above
        $this->assertEquals(1, $this->commandTester->getStatusCode());
    }

    public function testSeverityFilter(): void
    {
        $this->commandTester->execute([
            'path' => __DIR__ . '/../Fixtures/Laravel',
            '--output' => 'json',
            '--severity' => 'critical',
        ]);

        $output = $this->commandTester->getDisplay();
        $decoded = json_decode($output, true);

        if (!empty($decoded['findings'])) {
            foreach ($decoded['findings'] as $finding) {
                $this->assertEquals('Critical', $finding['severity']);
            }
        }
    }

    public function testOutputToFile(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'apiposture_test_');

        $this->commandTester->execute([
            'path' => __DIR__ . '/../Fixtures/Laravel',
            '--output' => 'json',
            '--output-file' => $tmpFile,
        ]);

        $this->assertFileExists($tmpFile);
        $content = file_get_contents($tmpFile);
        $decoded = json_decode($content, true);
        $this->assertNotNull($decoded);

        unlink($tmpFile);
    }

    public function testNoColorOption(): void
    {
        $this->commandTester->execute([
            'path' => __DIR__ . '/../Fixtures/Laravel',
            '--output' => 'terminal',
            '--no-color' => true,
        ]);

        // Should not error
        $this->assertIsString($this->commandTester->getDisplay());
    }

    public function testNoIconsOption(): void
    {
        $this->commandTester->execute([
            'path' => __DIR__ . '/../Fixtures/Laravel',
            '--output' => 'terminal',
            '--no-icons' => true,
        ]);

        $output = $this->commandTester->getDisplay();
        $this->assertStringNotContainsString('🔍', $output);
    }
}
