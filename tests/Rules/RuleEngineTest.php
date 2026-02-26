<?php

declare(strict_types=1);

namespace ApiPosture\Tests\Rules;

use ApiPosture\Core\Config\Configuration;
use ApiPosture\Core\Model\AuthorizationInfo;
use ApiPosture\Core\Model\Endpoint;
use ApiPosture\Core\Model\Enums\EndpointType;
use ApiPosture\Core\Model\Enums\HttpMethod;
use ApiPosture\Core\Model\Enums\SecurityClassification;
use ApiPosture\Core\Model\SourceLocation;
use ApiPosture\Rules\RuleEngine;
use PHPUnit\Framework\TestCase;

final class RuleEngineTest extends TestCase
{
    public function testRegistersAllDefaultRules(): void
    {
        $engine = new RuleEngine(new Configuration());
        $engine->registerDefaults();

        $rules = $engine->getRules();
        $this->assertCount(8, $rules);

        $ruleIds = array_map(fn($r) => $r->getId(), $rules);
        $this->assertContains('AP001', $ruleIds);
        $this->assertContains('AP002', $ruleIds);
        $this->assertContains('AP003', $ruleIds);
        $this->assertContains('AP004', $ruleIds);
        $this->assertContains('AP005', $ruleIds);
        $this->assertContains('AP006', $ruleIds);
        $this->assertContains('AP007', $ruleIds);
        $this->assertContains('AP008', $ruleIds);
    }

    public function testEvaluatesAllRulesAgainstEndpoints(): void
    {
        $engine = new RuleEngine(new Configuration());
        $engine->registerDefaults();

        $endpoints = [
            new Endpoint(
                route: '/api/data',
                methods: [HttpMethod::POST],
                type: EndpointType::Route,
                location: new SourceLocation('test.php', 1),
                authorization: new AuthorizationInfo(),
                classification: SecurityClassification::Public,
            ),
        ];

        $findings = $engine->evaluate($endpoints);
        $this->assertNotEmpty($findings);

        $ruleIds = array_unique(array_map(fn($f) => $f->ruleId, $findings));
        // An unprotected POST should trigger AP001, AP002, AP004, AP008 at least
        $this->assertContains('AP001', $ruleIds);
        $this->assertContains('AP002', $ruleIds);
        $this->assertContains('AP004', $ruleIds);
        $this->assertContains('AP008', $ruleIds);
    }

    public function testRespectsDisabledRules(): void
    {
        $config = Configuration::fromArray([
            'rules' => [
                'AP001' => ['enabled' => false],
            ],
        ]);

        $engine = new RuleEngine($config);
        $engine->registerDefaults();

        $endpoints = [
            new Endpoint(
                route: '/api/status',
                methods: [HttpMethod::GET],
                type: EndpointType::Route,
                location: new SourceLocation('test.php', 1),
                authorization: new AuthorizationInfo(),
                classification: SecurityClassification::Public,
            ),
        ];

        $findings = $engine->evaluate($endpoints);
        $ruleIds = array_map(fn($f) => $f->ruleId, $findings);
        $this->assertNotContains('AP001', $ruleIds);
    }

    public function testRespectsSuppression(): void
    {
        $config = Configuration::fromArray([
            'suppressions' => [
                ['ruleId' => 'AP008', 'route' => '/api/status'],
            ],
        ]);

        $engine = new RuleEngine($config);
        $engine->registerDefaults();

        $endpoints = [
            new Endpoint(
                route: '/api/status',
                methods: [HttpMethod::GET],
                type: EndpointType::Route,
                location: new SourceLocation('test.php', 1),
                authorization: new AuthorizationInfo(),
                classification: SecurityClassification::Public,
            ),
        ];

        $findings = $engine->evaluate($endpoints);
        $ap008Findings = array_filter($findings, fn($f) => $f->ruleId === 'AP008');
        $this->assertEmpty($ap008Findings);
    }
}
