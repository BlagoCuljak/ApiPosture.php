<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Rules;

use ApiPosture\Core\Config\Configuration;
use ApiPosture\Core\Analyzer\ProjectAnalyzer;
use ApiPosture\Core\Model\Enums\Severity;
use ApiPosture\Rules\AP201_HardcodedSecret;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AP201Test extends TestCase
{
    private AP201_HardcodedSecret $rule;

    protected function setUp(): void
    {
        $this->rule = new AP201_HardcodedSecret();
    }

    /** @return array<string, array{0: string}> Secrets are assembled so push protection never sees a literal. */
    public static function secrets(): array
    {
        $a = str_repeat('A1b2', 25);
        return [
            'aws akia' => ['AK' . 'IA' . 'QWERTYUIOP12345X'],
            'aws asia' => ['AS' . 'IA' . 'QWERTYUIOP12345X'],
            'gcp' => ['AI' . 'za' . substr($a, 0, 35)],
            'github ghp' => ['gh' . 'p_' . substr($a, 0, 36)],
            'github gho' => ['gh' . 'o_' . substr($a, 0, 36)],
            'github pat' => ['github_' . 'pat_' . substr($a, 0, 82)],
            'gitlab' => ['gl' . 'pat-' . substr($a, 0, 24)],
            'stripe sk' => ['sk_' . 'live_' . substr($a, 0, 26)],
            'stripe rk' => ['rk_' . 'live_' . substr($a, 0, 26)],
            'slack token' => ['xo' . 'xb-' . '1234567890-abcdefghij'],
            'slack webhook' => ['https://hooks.' . 'slack.com/services/' . 'T12345678/B12345678/' . substr($a, 0, 24)],
            'sendgrid' => ['S' . 'G.' . substr($a, 0, 22) . '.' . substr($a, 0, 43)],
            'npm' => ['np' . 'm_' . substr($a, 0, 36)],
            'digitalocean' => ['dop' . '_v1_' . str_repeat('a1b2c3d4', 8)],
            'pem' => ['-----BEGIN ' . 'RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890abcdef']
        ];
    }

    #[DataProvider('secrets')]
    public function testDetectsSecret(string $secret): void
    {
        $findings = $this->rule->scanContent("<?php\n\$k = '" . $secret . "';\n", 'src/Service.php');
        $this->assertCount(1, $findings);
        $this->assertSame('AP201', $findings[0]->ruleId);
        $this->assertSame(Severity::High, $findings[0]->severity);
        $this->assertSame(2, $findings[0]->endpoint->location->lineNumber);
        $this->assertStringNotContainsString($secret, $findings[0]->message);
        $this->assertStringContainsString(substr($secret, 0, 4) . '…', $findings[0]->message);
    }

    public function testDetectsMultilinePem(): void
    {
        $content = "<?php\n\$k = <<<K\n-----BEGIN " . "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nK;\n";
        $this->assertCount(1, $this->rule->scanContent($content, 'src/a.php'));
    }

    public function testPemHeaderMentionedInCodeIsIgnored(): void
    {
        $content = "<?php\nif (str_contains(\$s, '-----BEGIN " . "PRIVATE KEY-----')) { return; }\n";
        $this->assertSame([], $this->rule->scanContent($content, 'src/a.php'));
    }

    public function testOneFindingPerLineAndType(): void
    {
        $s = 'AK' . 'IA' . 'QWERTYUIOP12345X';
        $t = 'AS' . 'IA' . 'QWERTYUIOP12345X';
        $findings = $this->rule->scanContent("<?php\n\$a = ['$s', '$t'];\n", 'src/a.php');
        $this->assertCount(1, $findings);
    }

    #[DataProvider('placeholders')]
    public function testPlaceholdersAreIgnored(string $line): void
    {
        $this->assertSame([], $this->rule->scanContent("<?php\n$line\n", 'src/a.php'));
    }

    /** @return array<string, array{0: string}> */
    public static function placeholders(): array
    {
        return [
            'aws doc key' => ["\$k = 'AKIAIOSFODNN7EXAMPLE';"],
            'xxxx' => ["\$k = 'sk_" . "live_XXXXXXXXXXXXXXXXXXXXXXXXXXXX';"],
            'changeme' => ["\$k = 'gh" . "p_changemechangemechangemechangemechange';"],
            'dummy' => ["\$k = 'np" . "m_dummydummydummydummydummydummydummyd';"],
            'fake' => ["\$k = 'AK" . "IAFAKEFAKEFAKEFAKE';"],
            'pk_live' => ["\$k = 'pk_" . "live_abcdefghijklmnopqrstuvwxyz';"],
            'generic password' => ['$password = "hunter2hunter2";'],
            'generic api key' => ["\$api_key = 'abcdefghijklmnopqrstuvwxyz123456';"],
            'jwt' => ["\$t = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk';"],
        ];
    }

    #[DataProvider('skippedPaths')]
    public function testSkippedPaths(string $path): void
    {
        $this->assertFalse(AP201_HardcodedSecret::shouldScan($path));
        $secret = 'AK' . 'IA' . 'QWERTYUIOP12345X';
        $this->assertSame([], $this->rule->scanContent("<?php \$k = '$secret';", $path));
    }

    /** @return array<string, array{0: string}> */
    public static function skippedPaths(): array
    {
        return array_map(fn($p) => [$p], [
            'test' => 'test/a.php', 'tests' => 'tests/Unit/a.php', 'spec' => 'spec/a.php',
            'fixtures' => 'app/fixtures/a.php', 'testdata' => 'testdata/a.php', 'samples' => 'samples/a.php',
            'examples' => 'examples/a.php', 'docs' => 'docs/a.php', 'vendor' => 'vendor/x/a.php',
            'node_modules' => 'node_modules/x/a.php', 'storage' => 'storage/framework/a.php',
            'cache' => 'bootstrap/cache/a.php', 'suffix' => 'src/FooTest.php', 'env example' => '.env.example',
        ]);
    }

    public function testCommittedEnvIsScanned(): void
    {
        $secret = 'sk_' . 'live_' . str_repeat('a1B2', 7);
        $findings = $this->rule->scanContent("APP_ENV=prod\nSTRIPE=$secret\n", '.env');
        $this->assertCount(1, $findings);
        $this->assertSame(2, $findings[0]->endpoint->location->lineNumber);
    }

    public function testAnalyzerHonoursDisableAndSuppression(): void
    {
        $dir = sys_get_temp_dir() . '/ap201_' . uniqid();
        mkdir($dir . '/src', 0777, true);
        file_put_contents($dir . '/src/a.php', "<?php\n\$k = '" . 'AK' . 'IA' . "QWERTYUIOP12345X';\n");

        $result = (new ProjectAnalyzer(new Configuration()))->scan($dir);
        $this->assertCount(1, $result->findings);
        $this->assertSame('AP201', $result->findings[0]->ruleId);

        $off = new Configuration(rules: ['AP201' => ['enabled' => false]]);
        $this->assertCount(0, (new ProjectAnalyzer($off))->scan($dir)->findings);

        $sup = new Configuration(suppressions: [['ruleId' => 'AP201', 'route' => 'src/*']]);
        $this->assertCount(0, (new ProjectAnalyzer($sup))->scan($dir)->findings);

        unlink($dir . '/src/a.php');
        rmdir($dir . '/src');
        rmdir($dir);
    }
}
