<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Actions\Decision;
use WPRTWAF\Actions\DecisionEngine;
use WPRTWAF\Actions\DecisionResult;
use WPRTWAF\Admin\Settings;
use WPRTWAF\Bootstrap\Kernel;
use WPRTWAF\Bootstrap\Plugin;
use WPRTWAF\Bootstrap\ServiceContainer;
use WPRTWAF\Http\ClientIpResolver;
use WPRTWAF\Http\PreFilter;
use WPRTWAF\Http\RequestContextFactory;
use WPRTWAF\Http\RequestNormalizer;
use WPRTWAF\Logging\EventLogger;
use WPRTWAF\Logging\LoggerFactory;
use WPRTWAF\Integrity\FileMonitor;
use WPRTWAF\Integrity\InMemoryBaselineStore;
use WPRTWAF\Integrity\MalwareScanner;
use WPRTWAF\RateLimit\RateLimiterInterface;
use WPRTWAF\Rules\RuleEngine;
use WPRTWAF\Rules\RuleRepository;

class PluginTest extends TestCase
{
    public function testRegisterBootstrapsServicesWithoutWordPressHooks(): void
    {
        $container = new ServiceContainer();

        $settings = new class extends Settings {
            public int $registered = 0;

            public function __construct()
            {
                parent::__construct();
            }

            public function register(): void
            {
                $this->registered++;
            }
        };

        $optionsProvider = static fn (): array => [
            'mode' => 'monitor',
            'trusted_proxies' => [],
            'ip_allowlist' => [],
            'ip_blocklist' => [],
            'user_agent_blocklist' => [],
            'rate_limit' => ['enabled' => false],
        ];

        $requestFactory = new RequestContextFactory();
        $clientIpResolver = new ClientIpResolver($optionsProvider);
        $normalizer = new RequestNormalizer($clientIpResolver);
        $preFilter = new PreFilter($optionsProvider, new class implements RateLimiterInterface {
            public function allow(\WPRTWAF\Http\NormalizedRequest $request): bool
            {
                return true;
            }
        });
        $ruleRepository = new RuleRepository();
        $ruleEngine = new RuleEngine($ruleRepository);
        $decisionEngine = new DecisionEngine($optionsProvider);

        $kernel = new class($requestFactory, $normalizer, $preFilter, $ruleEngine, $decisionEngine) extends Kernel {
            public int $handled = 0;

            public function __construct(
                RequestContextFactory $factory,
                RequestNormalizer $normalizer,
                PreFilter $preFilter,
                RuleEngine $ruleEngine,
                DecisionEngine $decisionEngine
            ) {
                parent::__construct($factory, $normalizer, $preFilter, $ruleEngine, $decisionEngine, new class extends EventLogger {
                    public function __construct()
                    {
                    }

                    public function logDecision(\WPRTWAF\Http\NormalizedRequest $request, DecisionResult $result): void
                    {
                    }
                });
            }

            public function handleRequest(): DecisionResult
            {
                $this->handled++;
                return new DecisionResult(Decision::ALLOW);
            }
        };

        $container->share(Settings::class, static fn (ServiceContainer $c): Settings => $settings);
        $container->share(RequestContextFactory::class, static fn (ServiceContainer $c): RequestContextFactory => $requestFactory);
        $container->share(ClientIpResolver::class, static fn (ServiceContainer $c): ClientIpResolver => $clientIpResolver);
        $container->share(RequestNormalizer::class, static fn (ServiceContainer $c): RequestNormalizer => $normalizer);
        $container->share(PreFilter::class, static fn (ServiceContainer $c): PreFilter => $preFilter);
        $container->share(RuleRepository::class, static fn (ServiceContainer $c): RuleRepository => $ruleRepository);
        $container->share(RuleEngine::class, static fn (ServiceContainer $c): RuleEngine => $ruleEngine);
        $container->share(DecisionEngine::class, static fn (ServiceContainer $c): DecisionEngine => $decisionEngine);
        $container->share(LoggerFactory::class, static fn (ServiceContainer $c): LoggerFactory => new LoggerFactory());
        $container->share(FileMonitor::class, static fn (ServiceContainer $c): FileMonitor => new FileMonitor(
            new InMemoryBaselineStore(),
            MalwareScanner::withDefaultPatterns(),
            static fn (): array => [
                'integrity' => [
                    'enabled' => false,
                    'auto_build' => false,
                    'quarantine' => false,
                    'include_core' => true,
                    'include_plugins' => true,
                    'include_themes' => true,
                    'malware_scan' => [
                        'enabled' => false,
                        'quarantine' => false,
                    ],
                ],
            ],
            static fn (): array => []
        ));
        $container->share(Kernel::class, static fn (ServiceContainer $c): Kernel => $kernel);

        $plugin = new Plugin($container);
        $plugin->register();

        $this->assertSame(1, $settings->registered);
        $this->assertSame(1, $kernel->handled);
    }
}
