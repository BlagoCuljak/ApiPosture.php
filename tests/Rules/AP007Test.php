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
use ApiPosture\Rules\AP007_SensitiveRouteKeywords;
use PHPUnit\Framework\TestCase;

final class AP007Test extends TestCase
{
    private AP007_SensitiveRouteKeywords $rule;

    protected function setUp(): void
    {
        $this->rule = new AP007_SensitiveRouteKeywords();
    }

    public function testFlagsAdminRouteWithoutAuth(): void
    {
        $endpoint = $this->makeEndpoint('/api/admin/dashboard', new AuthorizationInfo());
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
        $this->assertEquals('AP007', $findings[0]->ruleId);
        $this->assertEquals(Severity::High, $findings[0]->severity);
    }

    public function testFlagsDebugRouteWithoutAuth(): void
    {
        $endpoint = $this->makeEndpoint('/api/debug/info', new AuthorizationInfo());
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
        $this->assertEquals(Severity::High, $findings[0]->severity);
    }

    public function testLowerSeverityWithAuth(): void
    {
        $endpoint = $this->makeEndpoint('/api/admin/dashboard', new AuthorizationInfo(hasAuth: true));
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
        $this->assertEquals(Severity::Low, $findings[0]->severity);
    }

    public function testSkipsNonSensitiveRoute(): void
    {
        $endpoint = $this->makeEndpoint('/api/users', new AuthorizationInfo());
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    public function testFlagsExportRoute(): void
    {
        $endpoint = $this->makeEndpoint('/api/export/csv', new AuthorizationInfo());
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
    }

    public function testFlagsSecretRoute(): void
    {
        $endpoint = $this->makeEndpoint('/api/secret/keys', new AuthorizationInfo());
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
    }

    private function makeEndpoint(string $route, AuthorizationInfo $auth): Endpoint
    {
        return new Endpoint(
            route: $route,
            methods: [HttpMethod::GET],
            type: EndpointType::Route,
            location: new SourceLocation('test.php', 1),
            authorization: $auth,
            classification: $auth->hasAuth ? SecurityClassification::Authenticated : SecurityClassification::Public,
        );
    }
}
