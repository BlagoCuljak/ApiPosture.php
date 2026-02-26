<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Rules;

use ApiPosture\Core\Model\AuthorizationInfo;
use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\EndpointType;
use ApiPosture\Core\Model\Enums\HttpMethod;
use ApiPosture\Core\Model\Enums\SecurityClassification;
use ApiPosture\Core\Model\Enums\Severity;
use ApiPosture\Core\Model\SourceLocation;
use ApiPosture\Rules\AP004_MissingAuthOnWrites;
use PHPUnit\Framework\TestCase;

final class AP004Test extends TestCase
{
    private AP004_MissingAuthOnWrites $rule;

    protected function setUp(): void
    {
        $this->rule = new AP004_MissingAuthOnWrites();
    }

    public function testFlagsUnprotectedWriteEndpoint(): void
    {
        $endpoint = $this->makeEndpoint([HttpMethod::POST], new AuthorizationInfo());
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
        $this->assertEquals('AP004', $findings[0]->ruleId);
        $this->assertEquals(Severity::Critical, $findings[0]->severity);
    }

    public function testSkipsGetEndpoint(): void
    {
        $endpoint = $this->makeEndpoint([HttpMethod::GET], new AuthorizationInfo());
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    public function testSkipsAuthenticatedEndpoint(): void
    {
        $endpoint = $this->makeEndpoint([HttpMethod::POST], new AuthorizationInfo(hasAuth: true));
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    public function testSkipsExplicitlyAnonymous(): void
    {
        $endpoint = $this->makeEndpoint([HttpMethod::POST], new AuthorizationInfo(hasAllowAnonymous: true));
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    public function testSkipsEndpointWithMiddleware(): void
    {
        $endpoint = $this->makeEndpoint([HttpMethod::POST], new AuthorizationInfo(middleware: ['throttle']));
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    public function testFlagsDeleteEndpoint(): void
    {
        $endpoint = $this->makeEndpoint([HttpMethod::DELETE], new AuthorizationInfo());
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
    }

    public function testFlagsPutEndpoint(): void
    {
        $endpoint = $this->makeEndpoint([HttpMethod::PUT], new AuthorizationInfo());
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
    }

    private function makeEndpoint(array $methods, AuthorizationInfo $auth): Endpoint
    {
        return new Endpoint(
            route: '/api/test',
            methods: $methods,
            type: EndpointType::Route,
            location: new SourceLocation('test.php', 1),
            authorization: $auth,
            classification: SecurityClassification::Public,
        );
    }
}
