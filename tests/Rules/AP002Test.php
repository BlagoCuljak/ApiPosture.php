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
use ApiPosture\Rules\AP002_AllowAnonymousOnWrite;
use PHPUnit\Framework\TestCase;

final class AP002Test extends TestCase
{
    private AP002_AllowAnonymousOnWrite $rule;

    protected function setUp(): void
    {
        $this->rule = new AP002_AllowAnonymousOnWrite();
    }

    public function testFlagsPublicWriteEndpoint(): void
    {
        $endpoint = $this->makeEndpoint('/api/data', [HttpMethod::POST]);
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
        $this->assertEquals('AP002', $findings[0]->ruleId);
        $this->assertEquals(Severity::High, $findings[0]->severity);
    }

    public function testSkipsGetEndpoint(): void
    {
        $endpoint = $this->makeEndpoint('/api/data', [HttpMethod::GET]);
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    public function testSkipsAuthenticatedWriteEndpoint(): void
    {
        $endpoint = $this->makeEndpoint('/api/data', [HttpMethod::POST], new AuthorizationInfo(hasAuth: true));
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    public function testWebhookReducesSeverity(): void
    {
        $endpoint = $this->makeEndpoint('/api/webhook/stripe', [HttpMethod::POST]);
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
        $this->assertEquals(Severity::Medium, $findings[0]->severity);
    }

    public function testAuthEndpointReducesSeverity(): void
    {
        $endpoint = $this->makeEndpoint('/api/auth/login', [HttpMethod::POST]);
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
        $this->assertEquals(Severity::Low, $findings[0]->severity);
    }

    public function testAnalyticsReducesSeverity(): void
    {
        $endpoint = $this->makeEndpoint('/api/analytics/track', [HttpMethod::POST]);
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
        $this->assertEquals(Severity::Low, $findings[0]->severity);
    }

    public function testFlagsPutEndpoint(): void
    {
        $endpoint = $this->makeEndpoint('/api/data', [HttpMethod::PUT]);
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
    }

    public function testFlagsDeleteEndpoint(): void
    {
        $endpoint = $this->makeEndpoint('/api/data', [HttpMethod::DELETE]);
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
    }

    private function makeEndpoint(string $route, array $methods, ?AuthorizationInfo $auth = null): Endpoint
    {
        return new Endpoint(
            route: $route,
            methods: $methods,
            type: EndpointType::Route,
            location: new SourceLocation('test.php', 1),
            authorization: $auth ?? new AuthorizationInfo(),
            classification: SecurityClassification::Public,
        );
    }
}
