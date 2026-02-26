<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Core\Classification;

use ApiPosture\Core\Classification\SecurityClassifier;
use ApiPosture\Core\Model\AuthorizationInfo;
use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\EndpointType;
use ApiPosture\Core\Model\Enums\HttpMethod;
use ApiPosture\Core\Model\Enums\SecurityClassification;
use ApiPosture\Core\Model\SourceLocation;
use PHPUnit\Framework\TestCase;

final class SecurityClassifierTest extends TestCase
{
    private SecurityClassifier $classifier;

    protected function setUp(): void
    {
        $this->classifier = new SecurityClassifier();
    }

    public function testPublicEndpoint(): void
    {
        $endpoint = $this->makeEndpoint(new AuthorizationInfo());
        $this->assertEquals(SecurityClassification::Public, $this->classifier->classify($endpoint));
    }

    public function testExplicitlyPublicEndpoint(): void
    {
        $endpoint = $this->makeEndpoint(new AuthorizationInfo(hasAllowAnonymous: true));
        $this->assertEquals(SecurityClassification::Public, $this->classifier->classify($endpoint));
    }

    public function testAuthenticatedEndpoint(): void
    {
        $endpoint = $this->makeEndpoint(new AuthorizationInfo(hasAuth: true));
        $this->assertEquals(SecurityClassification::Authenticated, $this->classifier->classify($endpoint));
    }

    public function testRoleRestrictedEndpoint(): void
    {
        $endpoint = $this->makeEndpoint(new AuthorizationInfo(hasAuth: true, roles: ['admin']));
        $this->assertEquals(SecurityClassification::RoleRestricted, $this->classifier->classify($endpoint));
    }

    public function testPolicyRestrictedEndpoint(): void
    {
        $endpoint = $this->makeEndpoint(new AuthorizationInfo(hasAuth: true, policies: ['manage-users']));
        $this->assertEquals(SecurityClassification::PolicyRestricted, $this->classifier->classify($endpoint));
    }

    public function testPolicyTakesPrecedenceOverRole(): void
    {
        $endpoint = $this->makeEndpoint(new AuthorizationInfo(
            hasAuth: true,
            roles: ['admin'],
            policies: ['manage-users'],
        ));
        $this->assertEquals(SecurityClassification::PolicyRestricted, $this->classifier->classify($endpoint));
    }

    public function testClassifyAll(): void
    {
        $endpoints = [
            $this->makeEndpoint(new AuthorizationInfo()),
            $this->makeEndpoint(new AuthorizationInfo(hasAuth: true)),
            $this->makeEndpoint(new AuthorizationInfo(hasAuth: true, roles: ['admin'])),
        ];

        $classified = $this->classifier->classifyAll($endpoints);

        $this->assertEquals(SecurityClassification::Public, $classified[0]->classification);
        $this->assertEquals(SecurityClassification::Authenticated, $classified[1]->classification);
        $this->assertEquals(SecurityClassification::RoleRestricted, $classified[2]->classification);
    }

    private function makeEndpoint(AuthorizationInfo $auth): Endpoint
    {
        return new Endpoint(
            route: '/test',
            methods: [HttpMethod::GET],
            type: EndpointType::Route,
            location: new SourceLocation('test.php', 1),
            authorization: $auth,
        );
    }
}
