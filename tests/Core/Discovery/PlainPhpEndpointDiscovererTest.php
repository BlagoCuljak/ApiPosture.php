<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Core\Discovery;

use ApiPosture\Core\Discovery\PlainPhpEndpointDiscoverer;
use ApiPosture\Core\Model\Enums\HttpMethod;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;

final class PlainPhpEndpointDiscovererTest extends TestCase
{
    private PlainPhpEndpointDiscoverer $discoverer;
    private \PhpParser\Parser $parser;

    protected function setUp(): void
    {
        $this->discoverer = new PlainPhpEndpointDiscoverer();
        $this->parser = (new ParserFactory())->createForNewestSupportedVersion();
    }

    // --- supports() ---

    public function testSupportsFileWithPostData(): void
    {
        $code = '<?php if (isset($_POST["name"])) { echo "ok"; }';
        $ast = $this->parser->parse($code);
        $this->assertTrue($this->discoverer->supports($ast, 'form.php'));
    }

    public function testSupportsFileWithGetData(): void
    {
        $code = '<?php $id = $_GET["id"];';
        $ast = $this->parser->parse($code);
        $this->assertTrue($this->discoverer->supports($ast, 'show.php'));
    }

    public function testSupportsFileWithRequestMethodCheck(): void
    {
        $code = '<?php if ($_SERVER["REQUEST_METHOD"] === "POST") { }';
        $ast = $this->parser->parse($code);
        $this->assertTrue($this->discoverer->supports($ast, 'handler.php'));
    }

    public function testDoesNotSupportPureEchoFile(): void
    {
        $code = '<?php echo "Hello world";';
        $ast = $this->parser->parse($code);
        $this->assertFalse($this->discoverer->supports($ast, 'hello.php'));
    }

    public function testDoesNotSupportLaravelRouteFile(): void
    {
        $code = '<?php Route::get("/users", [UserController::class, "index"]);';
        $ast = $this->parser->parse($code);
        $this->assertFalse($this->discoverer->supports($ast, 'routes/web.php'));
    }

    // --- discover() route ---

    public function testRouteIsBasenameOfFile(): void
    {
        $code = '<?php $x = $_GET["q"];';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, '/var/www/html/search.php');

        $this->assertCount(1, $endpoints);
        $this->assertEquals('/search.php', $endpoints[0]->route);
    }

    // --- discover() method inference ---

    public function testInfersPostFromPostData(): void
    {
        $code = '<?php if (isset($_POST["email"])) { $email = $_POST["email"]; }';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'mail.php');

        $this->assertCount(1, $endpoints);
        $this->assertContains(HttpMethod::POST, $endpoints[0]->methods);
        $this->assertNotContains(HttpMethod::GET, $endpoints[0]->methods);
    }

    public function testInfersGetFromGetData(): void
    {
        $code = '<?php $id = $_GET["id"];';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'show.php');

        $this->assertCount(1, $endpoints);
        $this->assertContains(HttpMethod::GET, $endpoints[0]->methods);
        $this->assertNotContains(HttpMethod::POST, $endpoints[0]->methods);
    }

    public function testInfersBothMethodsFromRequestSuperglobal(): void
    {
        $code = '<?php $value = $_REQUEST["key"];';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'handle.php');

        $this->assertCount(1, $endpoints);
        $this->assertContains(HttpMethod::GET, $endpoints[0]->methods);
        $this->assertContains(HttpMethod::POST, $endpoints[0]->methods);
    }

    public function testInfersBothMethodsFromMixedSuperglobals(): void
    {
        $code = '<?php
            if (isset($_POST["save"])) { $title = $_POST["title"]; }
            $id = $_GET["id"];
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'tasks.php');

        $this->assertCount(1, $endpoints);
        $this->assertContains(HttpMethod::GET, $endpoints[0]->methods);
        $this->assertContains(HttpMethod::POST, $endpoints[0]->methods);
    }

    public function testInfersMethodFromServerRequestMethodComparison(): void
    {
        $code = '<?php if ($_SERVER["REQUEST_METHOD"] === "DELETE") { }';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'api.php');

        $this->assertCount(1, $endpoints);
        $this->assertContains(HttpMethod::DELETE, $endpoints[0]->methods);
    }

    public function testDefaultsToGetWhenOnlyServerSuperglobal(): void
    {
        $code = '<?php $host = $_SERVER["HTTP_HOST"];';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'page.php');

        $this->assertCount(1, $endpoints);
        $this->assertContains(HttpMethod::GET, $endpoints[0]->methods);
    }

    // --- discover() auth inference ---

    public function testNoAuthWhenNoSessionChecks(): void
    {
        $code = '<?php $id = $_GET["id"]; echo $id;';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'public.php');

        $this->assertFalse($endpoints[0]->authorization->hasAuth);
    }

    public function testDetectsAuthFromSessionUserKey(): void
    {
        $code = '<?php
            session_start();
            if (!isset($_SESSION["user_id"])) { header("Location: login.php"); exit; }
            $id = $_GET["id"];
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'dashboard.php');

        $this->assertTrue($endpoints[0]->authorization->hasAuth);
    }

    public function testDetectsAuthFromSessionLoggedInKey(): void
    {
        $code = '<?php
            if ($_SESSION["logged_in"] !== true) { die("Forbidden"); }
            $data = $_POST["data"];
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'admin.php');

        $this->assertTrue($endpoints[0]->authorization->hasAuth);
    }

    public function testSessionFlashMessageDoesNotTriggerAuth(): void
    {
        $code = '<?php
            session_start();
            if (isset($_SESSION["message"])) { echo $_SESSION["message"]; }
            $id = $_GET["id"];
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'index.php');

        $this->assertFalse($endpoints[0]->authorization->hasAuth);
    }
}
