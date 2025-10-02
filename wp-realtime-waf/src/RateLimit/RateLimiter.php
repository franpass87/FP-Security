<?php

namespace WPRTWAF\RateLimit;

use Closure;
use WPRTWAF\Http\NormalizedRequest;

class RateLimiter implements RateLimiterInterface
{
    /** @var Closure */
    private readonly Closure $optionsProvider;

    /** @var Closure */
    private readonly Closure $timeProvider;

    public function __construct(
        private readonly RateLimitStoreInterface $store,
        callable $optionsProvider,
        ?callable $timeProvider = null
    ) {
        $this->optionsProvider = Closure::fromCallable($optionsProvider);
        $this->timeProvider = $timeProvider !== null ? Closure::fromCallable($timeProvider) : static fn (): int => time();
    }

    public function allow(NormalizedRequest $request): bool
    {
        $config = $this->normalizeConfig(($this->optionsProvider)()['rate_limit'] ?? []);

        if (!$config['enabled']) {
            return true;
        }

        $now = ($this->timeProvider)();
        $ip = $request->getIp();

        if ($config['ip_max'] > 0 && $ip !== '') {
            $count = $this->store->increment($this->key('ip', $ip), $config['ip_window'], $now);
            if ($count > $config['ip_max']) {
                return false;
            }
        }

        if ($config['endpoint_max'] > 0 && $ip !== '') {
            $identifier = $ip . '|' . $request->getMethod() . '|' . $request->getPath();
            $count = $this->store->increment($this->key('ep', $identifier), $config['endpoint_window'], $now);
            if ($count > $config['endpoint_max']) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<string, mixed> $config
     * @return array{enabled: bool, ip_max: int, ip_window: int, endpoint_max: int, endpoint_window: int}
     */
    private function normalizeConfig(array $config): array
    {
        $enabled = (bool) ($config['enabled'] ?? false);

        $ipMax = $this->positiveInt($config['ip_max'] ?? 0);
        $ipWindow = max(1, $this->positiveInt($config['ip_window'] ?? 60));
        $endpointMax = $this->positiveInt($config['endpoint_max'] ?? 0);
        $endpointWindow = max(1, $this->positiveInt($config['endpoint_window'] ?? 60));

        return [
            'enabled' => $enabled,
            'ip_max' => $ipMax,
            'ip_window' => $ipWindow,
            'endpoint_max' => $endpointMax,
            'endpoint_window' => $endpointWindow,
        ];
    }

    private function key(string $prefix, string $value): string
    {
        return 'wprtwaf:' . $prefix . ':' . hash('sha256', $value);
    }

    private function positiveInt(mixed $value): int
    {
        $value = filter_var($value, FILTER_VALIDATE_INT);

        return $value !== false && $value > 0 ? (int) $value : 0;
    }
}
