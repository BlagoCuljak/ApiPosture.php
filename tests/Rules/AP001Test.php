<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Rules;

use ApiPosture\Core\Model\AuthorizationInfo;
use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\EndpointType;
use ApiPosture\Core\Model\Enums\HttpMethod;
use ApiPosture\Core\Model\Enums\SecurityClassification;
use ApiPosture\Core\Model\SourceLocation;
use ApiPosture\Rules\AP001_PublicWithoutExplicitIntent;
use PHPUnit\Framework\TestCase;

final class AP001Test extends TestCase
{
    private AP001_PublicWithoutExplicitIntent $rule;

    protected function setUp(): void
    {
        $this->rule = new AP001_PublicWithoutExplicitIntent();
    }

    public function testFlagsPublicWithoutExplicitIntent(): void
    {
        $endpoint = $this->makeEndpoint(
            classification: SecurityClassification::Public,
            auth: new AuthorizationInfo(),
        );
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
        $this->assertEquals('AP001', $findings[0]->ruleId);
    }

    public function testSkipsExplicitlyAnonymous(): void
    {
        $endpoint = $this->makeEndpoint(
            classification: SecurityClassification::Public,
            auth: new AuthorizationInfo(hasAllowAnonymous: true),
        );
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    public function testSkipsAuthenticated(): void
    {
        $endpoint = $this->makeEndpoint(
            classification: SecurityClassification::Authenticated,
            auth: new AuthorizationInfo(hasAuth: true),
        );
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    private function makeEndpoint(SecurityClassification $classification, AuthorizationInfo $auth): Endpoint
    {
        return new Endpoint(
            route: '/api/test',
            methods: [HttpMethod::GET],
            type: EndpointType::Route,
            location: new SourceLocation('test.php', 1),
            authorization: $auth,
            classification: $classification,
        );
    }
}
