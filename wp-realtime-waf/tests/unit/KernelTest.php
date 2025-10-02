<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Actions\Decision;
use WPRTWAF\Bootstrap\Kernel;
use WPRTWAF\Http\ClientIpResolver;
use WPRTWAF\Http\PreFilter;
use WPRTWAF\Http\RequestContext;
use WPRTWAF\Http\RequestContextFactory;
use WPRTWAF\Http\RequestNormalizer;
use WPRTWAF\RateLimit\RateLimiterInterface;
use WPRTWAF\Logging\EventLogger;
use WPRTWAF\Rules\RuleEngine;
use WPRTWAF\Rules\RuleRepository;

class KernelTest extends TestCase
{
    public function testKernelBlocksWhenRuleMatchesInBlockMode(): void
    {
        $options = [
            'mode' => 'block',
            'trusted_proxies' => [],
            'ip_allowlist' => [],
            'ip_blocklist' => [],
            'user_agent_blocklist' => [],
        ];

        $provider = function () use (&$options): array {
            return $options;
        };

        $resolver = new ClientIpResolver($provider);
        $normalizer = new RequestNormalizer($resolver);
        $prefilter = new PreFilter($provider, $this->alwaysAllowRateLimiter());
        $repository = new RuleRepository();
        $repository->setRules([
            [
                'id' => 'body-test',
                'pattern' => '/__ATTACK__/i',
                'targets' => ['body'],
                'action' => 'block',
                'type' => 'regex',
            ],
        ]);
        $engine = new RuleEngine($repository);
        $decisionEngine = new \WPRTWAF\Actions\DecisionEngine($provider);

        $context = new RequestContext(
            'POST',
            '/submit',
            ['user-agent' => 'Example'],
            [],
            ['payload' => '__ATTACK__'],
            [],
            '__ATTACK__',
            ['REMOTE_ADDR' => '198.51.100.10']
        );

        $factory = new class($context) extends RequestContextFactory {
            public function __construct(private readonly RequestContext $context)
            {
            }

            public function fromGlobals(): RequestContext
            {
                return $this->context;
            }
        };

        $kernel = new Kernel($factory, $normalizer, $prefilter, $engine, $decisionEngine, $this->noopLogger());

        $result = $kernel->handleRequest();

        $this->assertSame(Decision::BLOCK, $result->decision);
    }

    public function testKernelReturnsMonitorWhenModeIsMonitor(): void
    {
        $options = [
            'mode' => 'monitor',
            'trusted_proxies' => [],
            'ip_allowlist' => [],
            'ip_blocklist' => [],
            'user_agent_blocklist' => [],
        ];

        $provider = function () use (&$options): array {
            return $options;
        };

        $resolver = new ClientIpResolver($provider);
        $normalizer = new RequestNormalizer($resolver);
        $prefilter = new PreFilter($provider, $this->alwaysAllowRateLimiter());
        $repository = new RuleRepository();
        $repository->setRules([
            [
                'id' => 'body-test',
                'pattern' => '/__ATTACK__/i',
                'targets' => ['body'],
                'action' => 'block',
                'type' => 'regex',
            ],
        ]);
        $engine = new RuleEngine($repository);
        $decisionEngine = new \WPRTWAF\Actions\DecisionEngine($provider);

        $context = new RequestContext(
            'POST',
            '/submit',
            ['user-agent' => 'Example'],
            [],
            ['payload' => '__ATTACK__'],
            [],
            '__ATTACK__',
            ['REMOTE_ADDR' => '198.51.100.10']
        );

        $factory = new class($context) extends RequestContextFactory {
            public function __construct(private readonly RequestContext $context)
            {
            }

            public function fromGlobals(): RequestContext
            {
                return $this->context;
            }
        };

        $kernel = new Kernel($factory, $normalizer, $prefilter, $engine, $decisionEngine, $this->noopLogger());

        $result = $kernel->handleRequest();

        $this->assertSame(Decision::MONITOR, $result->decision);
    }

    public function testAllowlistSkipsRuleEvaluation(): void
    {
        $options = [
            'mode' => 'block',
            'trusted_proxies' => [],
            'ip_allowlist' => ['198.51.100.10'],
            'ip_blocklist' => [],
            'user_agent_blocklist' => [],
        ];

        $provider = function () use (&$options): array {
            return $options;
        };

        $resolver = new ClientIpResolver($provider);
        $normalizer = new RequestNormalizer($resolver);
        $prefilter = new PreFilter($provider, $this->alwaysAllowRateLimiter());
        $repository = new RuleRepository();
        $repository->setRules([
            [
                'id' => 'body-test',
                'pattern' => '/__ATTACK__/i',
                'targets' => ['body'],
                'action' => 'block',
                'type' => 'regex',
            ],
        ]);
        $engine = new RuleEngine($repository);
        $decisionEngine = new \WPRTWAF\Actions\DecisionEngine($provider);

        $context = new RequestContext(
            'POST',
            '/submit',
            ['user-agent' => 'Example'],
            [],
            ['payload' => '__ATTACK__'],
            [],
            '__ATTACK__',
            ['REMOTE_ADDR' => '198.51.100.10']
        );

        $factory = new class($context) extends RequestContextFactory {
            public function __construct(private readonly RequestContext $context)
            {
            }

            public function fromGlobals(): RequestContext
            {
                return $this->context;
            }
        };

        $kernel = new Kernel($factory, $normalizer, $prefilter, $engine, $decisionEngine, $this->noopLogger());

        $result = $kernel->handleRequest();

        $this->assertSame(Decision::ALLOW, $result->decision);
    }
    private function alwaysAllowRateLimiter(): RateLimiterInterface
    {
        return new class implements RateLimiterInterface {
            public function allow(\WPRTWAF\Http\NormalizedRequest $request): bool
            {
                return true;
            }
        };
    }

    private function noopLogger(): EventLogger
    {
        return new class extends EventLogger {
            public function __construct()
            {
            }

            public function logDecision(\WPRTWAF\Http\NormalizedRequest $request, \WPRTWAF\Actions\DecisionResult $result): void
            {
            }
        };
    }
}
