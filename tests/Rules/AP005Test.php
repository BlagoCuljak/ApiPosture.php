<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Rules;

use ApiPosture\Core\Model\AuthorizationInfo;
use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\EndpointType;
use ApiPosture\Core\Model\Enums\HttpMethod;
use ApiPosture\Core\Model\Enums\SecurityClassification;
use ApiPosture\Core\Model\SourceLocation;
use ApiPosture\Rules\AP005_ExcessiveRoleAccess;
use PHPUnit\Framework\TestCase;

final class AP005Test extends TestCase
{
    private AP005_ExcessiveRoleAccess $rule;

    protected function setUp(): void
    {
        $this->rule = new AP005_ExcessiveRoleAccess();
    }

    public function testFlagsExcessiveRoles(): void
    {
        $endpoint = $this->makeEndpoint(new AuthorizationInfo(
            hasAuth: true,
            roles: ['admin', 'editor', 'moderator', 'reviewer'],
        ));
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
        $this->assertEquals('AP005', $findings[0]->ruleId);
    }

    public function testSkipsThreeOrFewerRoles(): void
    {
        $endpoint = $this->makeEndpoint(new AuthorizationInfo(
            hasAuth: true,
            roles: ['admin', 'editor', 'moderator'],
        ));
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    public function testSkipsNoRoles(): void
    {
        $endpoint = $this->makeEndpoint(new AuthorizationInfo());
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    private function makeEndpoint(AuthorizationInfo $auth): Endpoint
    {
        return new Endpoint(
            route: '/api/test',
            methods: [HttpMethod::GET],
            type: EndpointType::Route,
            location: new SourceLocation('test.php', 1),
            authorization: $auth,
            classification: SecurityClassification::RoleRestricted,
        );
    }
}
