<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Rules;

use ApiPosture\Core\Model\AuthorizationInfo;
use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\EndpointType;
use ApiPosture\Core\Model\Enums\HttpMethod;
use ApiPosture\Core\Model\Enums\SecurityClassification;
use ApiPosture\Core\Model\SourceLocation;
use ApiPosture\Rules\AP003_ControllerActionConflict;
use PHPUnit\Framework\TestCase;

final class AP003Test extends TestCase
{
    private AP003_ControllerActionConflict $rule;

    protected function setUp(): void
    {
        $this->rule = new AP003_ControllerActionConflict();
    }

    public function testFlagsActionOverridingControllerAuth(): void
    {
        $endpoint = new Endpoint(
            route: '/api/users',
            methods: [HttpMethod::GET],
            type: EndpointType::Controller,
            location: new SourceLocation('test.php', 1),
            authorization: new AuthorizationInfo(
                hasAllowAnonymous: true,
                inheritedFrom: 'controller',
            ),
            classification: SecurityClassification::Public,
            controllerName: 'UserController',
            actionName: 'publicAction',
        );

        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(1, $findings);
        $this->assertEquals('AP003', $findings[0]->ruleId);
    }

    public function testSkipsNoInheritance(): void
    {
        $endpoint = new Endpoint(
            route: '/api/users',
            methods: [HttpMethod::GET],
            type: EndpointType::Route,
            location: new SourceLocation('test.php', 1),
            authorization: new AuthorizationInfo(),
            classification: SecurityClassification::Public,
        );

        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }

    public function testSkipsConsistentAuth(): void
    {
        $endpoint = new Endpoint(
            route: '/api/users',
            methods: [HttpMethod::GET],
            type: EndpointType::Controller,
            location: new SourceLocation('test.php', 1),
            authorization: new AuthorizationInfo(
                hasAuth: true,
                inheritedFrom: 'controller',
            ),
            classification: SecurityClassification::Authenticated,
            controllerName: 'UserController',
            actionName: 'index',
        );

        $findings = $this->rule->evaluate($endpoint);
        $this->assertCount(0, $findings);
    }
}
