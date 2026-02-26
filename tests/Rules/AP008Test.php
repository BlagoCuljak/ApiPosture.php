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
use ApiPosture\Rules\AP008_UnprotectedEndpoint;
use PHPUnit\Framework\TestCase;

final class AP008Test extends TestCase
{
    private AP008_UnprotectedEndpoint $rule;

    protected function setUp(): void
    {
        $this->rule = new AP008_UnprotectedEndpoint();
    }

    public function testFlagsUnprotectedGetEndpoint(): void
    {
        $endpoint = $this->makeEndpoint([HttpMethod::GET], new AuthorizationInfo());
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
        $this->assertEquals('AP008', $findings[0]->ruleId);
        $this->assertEquals(Severity::Info, $findings[0]->severity);
    }

    public function testHighSeverityForUnprotectedWriteEndpoint(): void
    {
        $endpoint = $this->makeEndpoint([HttpMethod::POST], new AuthorizationInfo());
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
        $this->assertEquals(Severity::High, $findings[0]->severity);
    }

    public function testSkipsAuthenticatedEndpoint(): void
    {
        $endpoint = $this->makeEndpoint([HttpMethod::GET], new AuthorizationInfo(hasAuth: true));
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    public function testSkipsExplicitlyAnonymous(): void
    {
        $endpoint = $this->makeEndpoint([HttpMethod::GET], new AuthorizationInfo(hasAllowAnonymous: true));
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    public function testSkipsEndpointWithMiddleware(): void
    {
        $endpoint = $this->makeEndpoint([HttpMethod::GET], new AuthorizationInfo(middleware: ['throttle']));
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
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
