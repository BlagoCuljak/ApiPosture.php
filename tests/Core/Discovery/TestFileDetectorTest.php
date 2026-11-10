<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Core\Discovery;

use ApiPosture\Core\Discovery\TestFileDetector;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;

final class TestFileDetectorTest extends TestCase
{
    private \PhpParser\Parser $parser;

    protected function setUp(): void
    {
        $this->parser = (new ParserFactory())->createForNewestSupportedVersion();
    }

    public function testDetectsTestFileBySuffix(): void
    {
        $ast = $this->parser->parse('<?php $router->get("/test/admin", fn () => null);');

        $this->assertTrue(TestFileDetector::isTestFile('/app/tests/Feature/UserAdminRouteTest.php', $ast));
        $this->assertTrue(TestFileDetector::isTestFile('C:\\app\\tests\\BaseTestCase.php', $ast));
        $this->assertTrue(TestFileDetector::isTestFile('/app/tests/api/LoginCest.php', $ast));
    }

    public function testDetectsTestClassByParent(): void
    {
        $ast = $this->parser->parse('<?php class RouteFixtures extends \Tests\TestCase {}');

        $this->assertTrue(TestFileDetector::isTestFile('/app/tests/RouteFixtures.php', $ast));
    }

    public function testDoesNotFlagApplicationCode(): void
    {
        $ast = $this->parser->parse('<?php
            class TestimonialController extends Controller {}
            Route::get("/testimonials", [TestimonialController::class, "index"]);
        ');

        $this->assertFalse(TestFileDetector::isTestFile('/app/routes/api.php', $ast));
        $this->assertFalse(TestFileDetector::isTestFile('/app/app/Http/Controllers/TestimonialController.php', $ast));
        $this->assertFalse(TestFileDetector::isTestFile('/app/routes/latest.php', $ast));
    }
}
