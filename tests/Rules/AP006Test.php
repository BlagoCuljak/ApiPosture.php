<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Rules;

use ApiPosture\Core\Model\AuthorizationInfo;
use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\EndpointType;
use ApiPosture\Core\Model\Enums\HttpMethod;
use ApiPosture\Core\Model\Enums\SecurityClassification;
use ApiPosture\Core\Model\SourceLocation;
use ApiPosture\Rules\AP006_WeakRoleNaming;
use PHPUnit\Framework\TestCase;

final class AP006Test extends TestCase
{
    private AP006_WeakRoleNaming $rule;

    protected function setUp(): void
    {
        $this->rule = new AP006_WeakRoleNaming();
    }

    public function testFlagsGenericRoleName(): void
    {
        $endpoint = $this->makeEndpoint(new AuthorizationInfo(hasAuth: true, roles: ['admin']));
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
        $this->assertEquals('AP006', $findings[0]->ruleId);
    }

    public function testFlagsUserRole(): void
    {
        $endpoint = $this->makeEndpoint(new AuthorizationInfo(hasAuth: true, roles: ['user']));
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
    }

    public function testSkipsSpecificRoleName(): void
    {
        $endpoint = $this->makeEndpoint(new AuthorizationInfo(hasAuth: true, roles: ['invoice_manager']));
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    public function testSkipsNoRoles(): void
    {
        $endpoint = $this->makeEndpoint(new AuthorizationInfo());
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    public function testFlagsROLE_ADMIN(): void
    {
        $endpoint = $this->makeEndpoint(new AuthorizationInfo(hasAuth: true, roles: ['ROLE_ADMIN']));
        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
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
