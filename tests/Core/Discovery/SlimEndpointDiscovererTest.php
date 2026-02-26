<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Core\Discovery;

use ApiPosture\Core\Discovery\SlimEndpointDiscoverer;
use ApiPosture\Core\Model\Enums\HttpMethod;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;

final class SlimEndpointDiscovererTest extends TestCase
{
    private SlimEndpointDiscoverer $discoverer;
    private \PhpParser\Parser $parser;

    protected function setUp(): void
    {
        $this->discoverer = new SlimEndpointDiscoverer();
        $this->parser = (new ParserFactory())->createForNewestSupportedVersion();
    }

    public function testSupportsSlimRoutes(): void
    {
        $code = '<?php $app->get("/api/test", function ($req, $res) {});';
        $ast = $this->parser->parse($code);
        $this->assertTrue($this->discoverer->supports($ast, 'routes.php'));
    }

    public function testDoesNotSupportPlainPhp(): void
    {
        $code = '<?php echo "hello";';
        $ast = $this->parser->parse($code);
        $this->assertFalse($this->discoverer->supports($ast, 'test.php'));
    }

    public function testDiscoversGetRoute(): void
    {
        $code = '<?php $app->get("/api/users", function ($req, $res) { return $res; });';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes.php');

        $this->assertCount(1, $endpoints);
        $this->assertEquals('/api/users', $endpoints[0]->route);
        $this->assertEquals([HttpMethod::GET], $endpoints[0]->methods);
    }

    public function testDiscoversPostRoute(): void
    {
        $code = '<?php $app->post("/api/users", function ($req, $res) {});';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes.php');

        $this->assertCount(1, $endpoints);
        $this->assertEquals([HttpMethod::POST], $endpoints[0]->methods);
    }

    public function testDiscoversMultipleRoutes(): void
    {
        $code = '<?php
            $app->get("/api/users", function ($req, $res) {});
            $app->post("/api/users", function ($req, $res) {});
            $app->put("/api/users/{id}", function ($req, $res) {});
            $app->delete("/api/users/{id}", function ($req, $res) {});
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes.php');

        $this->assertCount(4, $endpoints);
    }

    public function testDiscoversPatchRoute(): void
    {
        $code = '<?php $app->patch("/api/users/{id}", function ($req, $res) {});';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes.php');

        $this->assertCount(1, $endpoints);
        $this->assertEquals([HttpMethod::PATCH], $endpoints[0]->methods);
    }

    public function testNoAuthByDefault(): void
    {
        $code = '<?php $app->get("/api/status", function ($req, $res) {});';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes.php');

        $this->assertCount(1, $endpoints);
        $this->assertFalse($endpoints[0]->authorization->hasAuth);
    }

    public function testSupportsGroupCalls(): void
    {
        $code = '<?php
            $app->group("/api", function ($group) {
                $group->get("/users", function ($req, $res) {});
            });
        ';
        $ast = $this->parser->parse($code);
        $this->assertTrue($this->discoverer->supports($ast, 'routes.php'));
    }

    public function testDoesNotMatchSingleArgumentGet(): void
    {
        $code = '<?php $request->session()->get("status");';
        $ast = $this->parser->parse($code);
        $this->assertFalse($this->discoverer->supports($ast, 'controller.php'));
    }

    public function testDoesNotDiscoverFalsePositiveEndpoints(): void
    {
        $code = '<?php
            $request->session()->get("status");
            $cache->get("some_key");
            $collection->get("item");
            $config->get("database.host", "localhost");
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'service.php');
        $this->assertCount(0, $endpoints);
    }

    public function testDiscoversMapRoute(): void
    {
        $code = '<?php $app->map(["GET", "POST"], "/api/users", function ($req, $res) {});';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes.php');

        $this->assertCount(1, $endpoints);
        $this->assertEquals('/api/users', $endpoints[0]->route);
        $this->assertContains(HttpMethod::GET, $endpoints[0]->methods);
        $this->assertContains(HttpMethod::POST, $endpoints[0]->methods);
    }

    public function testDiscoversRouteWithInvokableClassStringHandler(): void
    {
        $code = '<?php $app->any("/user", "MyRestfulController");';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes.php');

        $this->assertCount(1, $endpoints);
        $this->assertEquals('/user', $endpoints[0]->route);
    }

    public function testDiscoversEmptyPathRouteInsideGroup(): void
    {
        $code = '<?php
            $app->group("/users/{id}", function ($group) {
                $group->map(["GET", "DELETE"], "", function ($req, $res) {});
            });
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'routes.php');

        $this->assertCount(1, $endpoints);
        $this->assertContains(HttpMethod::GET, $endpoints[0]->methods);
        $this->assertContains(HttpMethod::DELETE, $endpoints[0]->methods);
    }
}
