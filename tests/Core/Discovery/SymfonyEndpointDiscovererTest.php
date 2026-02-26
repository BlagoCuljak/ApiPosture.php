<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Core\Discovery;

use ApiPosture\Core\Discovery\SymfonyEndpointDiscoverer;
use ApiPosture\Core\Model\Enums\HttpMethod;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;

final class SymfonyEndpointDiscovererTest extends TestCase
{
    private SymfonyEndpointDiscoverer $discoverer;
    private \PhpParser\Parser $parser;

    protected function setUp(): void
    {
        $this->discoverer = new SymfonyEndpointDiscoverer();
        $this->parser = (new ParserFactory())->createForNewestSupportedVersion();
    }

    public function testSupportsSymfonyController(): void
    {
        $code = '<?php
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            use Symfony\Component\Routing\Attribute\Route;

            class UserController extends AbstractController
            {
                #[Route("/api/users", methods: ["GET"])]
                public function index() {}
            }
        ';
        $ast = $this->parser->parse($code);
        $this->assertTrue($this->discoverer->supports($ast, 'src/Controller/UserController.php'));
    }

    public function testDoesNotSupportPlainPhp(): void
    {
        $code = '<?php echo "hello";';
        $ast = $this->parser->parse($code);
        $this->assertFalse($this->discoverer->supports($ast, 'test.php'));
    }

    public function testDiscoversRouteAttribute(): void
    {
        $code = '<?php
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            use Symfony\Component\Routing\Attribute\Route;

            class UserController extends AbstractController
            {
                #[Route("/api/users", methods: ["GET"])]
                public function index() {}
            }
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'src/Controller/UserController.php');

        $this->assertCount(1, $endpoints);
        $this->assertEquals('/api/users', $endpoints[0]->route);
        $this->assertEquals([HttpMethod::GET], $endpoints[0]->methods);
        $this->assertEquals('UserController', $endpoints[0]->controllerName);
        $this->assertEquals('index', $endpoints[0]->actionName);
    }

    public function testDiscoversMultipleMethods(): void
    {
        $code = '<?php
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            use Symfony\Component\Routing\Attribute\Route;

            class UserController extends AbstractController
            {
                #[Route("/api/users", methods: ["GET"])]
                public function index() {}

                #[Route("/api/users", methods: ["POST"])]
                public function create() {}

                #[Route("/api/users/{id}", methods: ["PUT"])]
                public function update() {}
            }
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'src/Controller/UserController.php');

        $this->assertCount(3, $endpoints);
    }

    public function testDetectsIsGrantedAttribute(): void
    {
        $code = '<?php
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\Security\Http\Attribute\IsGranted;

            class AdminController extends AbstractController
            {
                #[Route("/api/admin", methods: ["GET"])]
                #[IsGranted("ROLE_ADMIN")]
                public function index() {}
            }
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'src/Controller/AdminController.php');

        $this->assertCount(1, $endpoints);
        $this->assertTrue($endpoints[0]->authorization->hasAuth);
        $this->assertContains('ROLE_ADMIN', $endpoints[0]->authorization->roles);
    }

    public function testClassLevelIsGranted(): void
    {
        $code = '<?php
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\Security\Http\Attribute\IsGranted;

            #[IsGranted("ROLE_ADMIN")]
            class AdminController extends AbstractController
            {
                #[Route("/api/admin/dashboard", methods: ["GET"])]
                public function dashboard() {}
            }
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'src/Controller/AdminController.php');

        $this->assertCount(1, $endpoints);
        $this->assertTrue($endpoints[0]->authorization->hasAuth);
        $this->assertContains('ROLE_ADMIN', $endpoints[0]->authorization->roles);
    }

    public function testClassRoutePrefix(): void
    {
        $code = '<?php
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            use Symfony\Component\Routing\Attribute\Route;

            #[Route("/api/users")]
            class UserController extends AbstractController
            {
                #[Route("/", methods: ["GET"])]
                public function index() {}

                #[Route("/{id}", methods: ["DELETE"])]
                public function delete() {}
            }
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'src/Controller/UserController.php');

        $this->assertCount(2, $endpoints);
        $this->assertEquals('/api/users/', $endpoints[0]->route);
        $this->assertEquals('/api/users/{id}', $endpoints[1]->route);
    }

    public function testPolicyBasedIsGranted(): void
    {
        $code = '<?php
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\Security\Http\Attribute\IsGranted;

            class PostController extends AbstractController
            {
                #[Route("/api/posts/{id}", methods: ["PUT"])]
                #[IsGranted("edit", subject: "post")]
                public function edit() {}
            }
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'src/Controller/PostController.php');

        $this->assertCount(1, $endpoints);
        $this->assertTrue($endpoints[0]->authorization->hasAuth);
        $this->assertContains('edit', $endpoints[0]->authorization->policies);
    }

    public function testDefaultsToGetWhenNoMethodsSpecified(): void
    {
        $code = '<?php
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            use Symfony\Component\Routing\Attribute\Route;

            class HomeController extends AbstractController
            {
                #[Route("/")]
                public function index() {}
            }
        ';
        $ast = $this->parser->parse($code);
        $endpoints = $this->discoverer->discover($ast, 'src/Controller/HomeController.php');

        $this->assertCount(1, $endpoints);
        $this->assertEquals([HttpMethod::GET], $endpoints[0]->methods);
    }
}
