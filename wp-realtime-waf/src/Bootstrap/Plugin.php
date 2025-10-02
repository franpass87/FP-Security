<?php

namespace WPRTWAF\Bootstrap;

use WPRTWAF\Actions\DecisionEngine;
use WPRTWAF\Auth\LoginAttemptStoreInterface;
use WPRTWAF\Auth\LoginLimiter;
use WPRTWAF\Auth\OptionsLoginAttemptStore;
use WPRTWAF\Auth\RestGuard;
use WPRTWAF\Auth\XmlRpcGuard;
use WPRTWAF\Admin\Settings;
use WPRTWAF\Http\ClientIpResolver;
use WPRTWAF\Integrity\BaselineStoreInterface;
use WPRTWAF\Integrity\FileMonitor;
use WPRTWAF\Integrity\MalwareScanner;
use WPRTWAF\Integrity\OptionsBaselineStore;
use WPRTWAF\Http\PreFilter;
use WPRTWAF\Http\RequestContextFactory;
use WPRTWAF\Http\RequestNormalizer;
use WPRTWAF\Logging\AlertManager;
use WPRTWAF\Logging\EventLogger;
use WPRTWAF\Logging\EventStoreInterface;
use WPRTWAF\Logging\LogExporter;
use WPRTWAF\Logging\LoggerFactory;
use WPRTWAF\Logging\OptionsEventStore;
use WPRTWAF\RateLimit\FallbackRateLimitStore;
use WPRTWAF\RateLimit\OptionsRateLimitStore;
use WPRTWAF\RateLimit\RateLimiter;
use WPRTWAF\RateLimit\RateLimiterInterface;
use WPRTWAF\RateLimit\RedisRateLimitStore;
use WPRTWAF\Rules\RuleEngine;
use WPRTWAF\Rules\RuleLoader;
use WPRTWAF\Rules\RuleFeedUpdater;
use WPRTWAF\Rules\RuleRepository;
use WPRTWAF\Rules\RuleManager;

class Plugin
{
    private bool $redisChecked = false;

    private ?object $redisClient = null;

    public function __construct(private readonly ServiceContainer $container)
    {
    }

    public function register(): void
    {
        $this->registerDefaultServices();

        if (function_exists('add_action')) {
            add_action('muplugins_loaded', [$this, 'onBootstrap'], 1);
        } else {
            $this->onBootstrap();
        }
    }

    public function onBootstrap(): void
    {
        $this->container->get(Settings::class)->register();

        $this->container->get(LoginLimiter::class)->register();
        $this->container->get(RestGuard::class)->register();
        $this->container->get(XmlRpcGuard::class)->register();

        $fileMonitor = $this->container->get(FileMonitor::class);
        $fileMonitor->register();
        $fileMonitor->maybePrimeBaseline();

        $ruleRepository = $this->container->get(RuleRepository::class);
        $ruleLoader = $this->container->get(RuleLoader::class);
        $ruleRepository->setRules($ruleLoader->load());

        $this->container->get(RuleFeedUpdater::class)->maybeUpdate();

        $this->container->get(RuleManager::class)->bootstrap();

        $this->container->get(Kernel::class)->handleRequest();
    }

    private function registerDefaultServices(): void
    {
        $optionsProvider = function (): array {
            return $this->container->get(Settings::class)->getOptions();
        };

        if (!$this->container->has(EventStoreInterface::class)) {
            $this->container->share(EventStoreInterface::class, static fn (ServiceContainer $container): EventStoreInterface => new OptionsEventStore());
        }

        if (!$this->container->has(LogExporter::class)) {
            $this->container->share(LogExporter::class, static fn (ServiceContainer $container): LogExporter => new LogExporter());
        }

        if (!$this->container->has(RuleRepository::class)) {
            $this->container->share(RuleRepository::class, static fn (ServiceContainer $container): RuleRepository => new RuleRepository());
        }

        if (!$this->container->has(RuleLoader::class)) {
            $rulesDir = dirname(__DIR__, 2) . '/rules/builtin';
            $this->container->share(RuleLoader::class, fn (ServiceContainer $container): RuleLoader => new RuleLoader($rulesDir));
        }

        if (!$this->container->has(RuleFeedUpdater::class)) {
            $feedPath = dirname(__DIR__, 2) . '/rules/feed/local-feed.json';
            $secret = 'wprtwaf-local-feed-secret';
            $this->container->share(
                RuleFeedUpdater::class,
                static fn (ServiceContainer $container): RuleFeedUpdater => new RuleFeedUpdater(
                    $container->get(RuleRepository::class),
                    $feedPath,
                    $secret,
                    static function (string $key, mixed $default = []): mixed {
                        if (function_exists('get_option')) {
                            return get_option($key, $default);
                        }

                        return $default;
                    },
                    static function (string $key, array $value): void {
                        if (function_exists('update_option')) {
                            update_option($key, $value);
                        }
                    }
                )
            );
        }

        if (!$this->container->has(RuleManager::class)) {
            $this->container->share(RuleManager::class, static fn (ServiceContainer $container): RuleManager => new RuleManager($container->get(RuleRepository::class)));
        }

        if (!$this->container->has(Settings::class)) {
            $this->container->share(
                Settings::class,
                fn (ServiceContainer $container): Settings => new Settings(
                    $container->get(EventStoreInterface::class),
                    $container->get(LogExporter::class),
                    $container->get(RuleManager::class)
                )
            );
        }

        if (!$this->container->has(RequestContextFactory::class)) {
            $this->container->share(RequestContextFactory::class, static fn (ServiceContainer $container): RequestContextFactory => new RequestContextFactory());
        }

        if (!$this->container->has(ClientIpResolver::class)) {
            $this->container->share(ClientIpResolver::class, fn (ServiceContainer $container): ClientIpResolver => new ClientIpResolver($optionsProvider));
        }

        if (!$this->container->has(LoginAttemptStoreInterface::class)) {
            $this->container->share(LoginAttemptStoreInterface::class, static fn (ServiceContainer $container): LoginAttemptStoreInterface => new OptionsLoginAttemptStore());
        }

        if (!$this->container->has(RequestNormalizer::class)) {
            $this->container->share(RequestNormalizer::class, fn (ServiceContainer $container): RequestNormalizer => new RequestNormalizer($container->get(ClientIpResolver::class)));
        }

        if (!$this->container->has(LoginLimiter::class)) {
            $this->container->share(
                LoginLimiter::class,
                fn (ServiceContainer $container): LoginLimiter => new LoginLimiter(
                    $container->get(LoginAttemptStoreInterface::class),
                    $container->get(ClientIpResolver::class),
                    $optionsProvider
                )
            );
        }

        if (!$this->container->has(RestGuard::class)) {
            $this->container->share(RestGuard::class, static fn (ServiceContainer $container): RestGuard => new RestGuard($optionsProvider));
        }

        if (!$this->container->has(XmlRpcGuard::class)) {
            $this->container->share(XmlRpcGuard::class, static fn (ServiceContainer $container): XmlRpcGuard => new XmlRpcGuard($optionsProvider));
        }

        if (!$this->container->has(RateLimiterInterface::class)) {
            $this->container->share(
                RateLimiterInterface::class,
                function (ServiceContainer $container) use ($optionsProvider): RateLimiterInterface {
                    $optionsStore = new OptionsRateLimitStore();
                    $redisClient = $this->resolveRedisClient();

                    if ($redisClient !== null) {
                        $store = new FallbackRateLimitStore(new RedisRateLimitStore($redisClient), $optionsStore);
                    } else {
                        $store = $optionsStore;
                    }

                    return new RateLimiter($store, $optionsProvider);
                }
            );
        }

        if (!$this->container->has(PreFilter::class)) {
            $this->container->share(
                PreFilter::class,
                fn (ServiceContainer $container): PreFilter => new PreFilter(
                    $optionsProvider,
                    $container->get(RateLimiterInterface::class)
                )
            );
        }

        if (!$this->container->has(RuleEngine::class)) {
            $this->container->share(RuleEngine::class, fn (ServiceContainer $container): RuleEngine => new RuleEngine($container->get(RuleRepository::class)));
        }

        if (!$this->container->has(DecisionEngine::class)) {
            $this->container->share(DecisionEngine::class, fn (ServiceContainer $container): DecisionEngine => new DecisionEngine($optionsProvider));
        }

        if (!$this->container->has(Kernel::class)) {
            $this->container->share(
                Kernel::class,
                fn (ServiceContainer $container): Kernel => new Kernel(
                    $container->get(RequestContextFactory::class),
                    $container->get(RequestNormalizer::class),
                    $container->get(PreFilter::class),
                    $container->get(RuleEngine::class),
                    $container->get(DecisionEngine::class),
                    $container->get(EventLogger::class)
                )
            );
        }

        if (!$this->container->has(BaselineStoreInterface::class)) {
            $this->container->share(BaselineStoreInterface::class, static fn (ServiceContainer $container): BaselineStoreInterface => new OptionsBaselineStore());
        }

        if (!$this->container->has(MalwareScanner::class)) {
            $this->container->share(MalwareScanner::class, static fn (ServiceContainer $container): MalwareScanner => MalwareScanner::withDefaultPatterns());
        }

        if (!$this->container->has(FileMonitor::class)) {
            $this->container->share(
                FileMonitor::class,
                fn (ServiceContainer $container): FileMonitor => new FileMonitor(
                    $container->get(BaselineStoreInterface::class),
                    $container->get(MalwareScanner::class),
                    $optionsProvider
                )
            );
        }

        if (!$this->container->has(LoggerFactory::class)) {
            $this->container->share(LoggerFactory::class, static fn (ServiceContainer $container): LoggerFactory => new LoggerFactory());
        }

        if (!$this->container->has(AlertManager::class)) {
            $this->container->share(
                AlertManager::class,
                fn (ServiceContainer $container): AlertManager => new AlertManager($optionsProvider)
            );
        }

        if (!$this->container->has(EventLogger::class)) {
            $this->container->share(
                EventLogger::class,
                fn (ServiceContainer $container): EventLogger => new EventLogger(
                    $container->get(EventStoreInterface::class),
                    $container->get(LoggerFactory::class)->create('security'),
                    $optionsProvider,
                    $container->get(AlertManager::class)
                )
            );
        }
    }

    private function resolveRedisClient(): ?object
    {
        if ($this->redisChecked) {
            return $this->redisClient;
        }

        $this->redisChecked = true;

        if (function_exists('apply_filters')) {
            $provided = apply_filters('wp_realtime_waf_redis_client', null);
            if (is_object($provided)) {
                return $this->redisClient = $provided;
            }
        }

        if (!class_exists('Predis\\Client')) {
            return $this->redisClient = null;
        }

        $parameters = $this->defaultRedisParameters();
        $options = [];

        if (function_exists('apply_filters')) {
            $parameters = apply_filters('wp_realtime_waf_redis_parameters', $parameters);
            $options = apply_filters('wp_realtime_waf_redis_options', $options);
        }

        if ($parameters === null) {
            return $this->redisClient = null;
        }

        try {
            $client = new \Predis\Client($parameters, $options);
            $client->connect();

            return $this->redisClient = $client;
        } catch (\Throwable $exception) {
            return $this->redisClient = null;
        }
    }

    private function defaultRedisParameters(): ?array
    {
        $host = null;

        if (defined('WP_REDIS_HOST')) {
            $host = (string) WP_REDIS_HOST;
        }

        if ($host === null) {
            $envHost = getenv('WP_REDIS_HOST');
            if ($envHost === false) {
                $envHost = getenv('WPRTWAF_REDIS_HOST');
            }

            if (is_string($envHost) && $envHost !== '') {
                $host = $envHost;
            }
        }

        if ($host === null || $host === '') {
            return null;
        }

        $port = 6379;

        if (defined('WP_REDIS_PORT')) {
            $port = (int) WP_REDIS_PORT;
        } else {
            $envPort = getenv('WP_REDIS_PORT');
            if ($envPort === false) {
                $envPort = getenv('WPRTWAF_REDIS_PORT');
            }

            if ($envPort !== false) {
                $port = (int) $envPort;
            }
        }

        return [
            'scheme' => 'tcp',
            'host' => $host,
            'port' => $port,
        ];
    }
}
