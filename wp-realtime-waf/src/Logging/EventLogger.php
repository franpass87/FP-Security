<?php

namespace WPRTWAF\Logging;

use Psr\Log\LoggerInterface;
use WPRTWAF\Actions\Decision;
use WPRTWAF\Actions\DecisionResult;
use WPRTWAF\Http\NormalizedRequest;

class EventLogger
{
    /** @var \Closure */
    private readonly \Closure $optionsProvider;

    public function __construct(
        private readonly EventStoreInterface $store,
        private readonly LoggerInterface $logger,
        callable $optionsProvider,
        private readonly AlertManager $alertManager
    ) {
        $this->optionsProvider = \Closure::fromCallable($optionsProvider);
    }

    public function logDecision(NormalizedRequest $request, DecisionResult $result): void
    {
        $options = ($this->optionsProvider)();
        $logging = is_array($options['logging'] ?? null) ? $options['logging'] : [];
        $maxEvents = is_int($logging['max_events'] ?? null) ? (int) $logging['max_events'] : 500;
        $this->store->setMaxEvents($maxEvents);

        $mode = $this->normalizeDecision($options['mode'] ?? Decision::MONITOR);
        $rule = $result->match?->getRule() ?? [];
        $severity = $this->normalizeSeverity($rule['severity'] ?? ($logging['default_severity'] ?? 'medium'));
        $ip = $request->getIp();

        if (!empty($logging['anonymize_ip'])) {
            $ip = $this->anonymizeIp($ip);
        }

        $event = Event::create(
            $this->normalizeDecision($result->decision),
            $severity,
            $ip,
            $request->getPath(),
            $request->getMethod(),
            (string) ($result->reason ?? 'unknown'),
            is_string($rule['id'] ?? null) ? $rule['id'] : null,
            $mode,
            $result->match?->getTarget() ?? 'request',
            $result->match?->getMatches() ?? [],
            $request->getUserAgent(),
            [
                'headers' => $this->filterHeaders($request->getHeaders()),
                'query' => $request->getQuery(),
                'cookies' => $request->getCookies(),
            ]
        );

        $this->store->append($event);
        $this->logger->info('wp-realtime-waf decision', $event->toArray());
        $this->alertManager->handle($event);
    }

    /**
     * @param array<string, string> $headers
     * @return array<string, string>
     */
    private function filterHeaders(array $headers): array
    {
        $filtered = [];
        foreach ($headers as $key => $value) {
            $filtered[strtolower((string) $key)] = substr((string) $value, 0, 256);
        }

        return $filtered;
    }

    private function anonymizeIp(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $parts = explode(':', $ip);
            if (count($parts) > 2) {
                $parts = array_pad($parts, 8, '0');
                $parts[6] = '0000';
                $parts[7] = '0000';
            }

            return implode(':', $parts);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            if (count($parts) === 4) {
                $parts[3] = '0';
            }

            return implode('.', $parts);
        }

        return $ip;
    }

    private function normalizeSeverity(mixed $severity): string
    {
        $value = strtolower(is_string($severity) ? $severity : 'medium');
        return match ($value) {
            'critical', 'high', 'medium', 'low' => $value,
            default => 'medium',
        };
    }

    private function normalizeDecision(mixed $decision): string
    {
        $value = strtolower(is_string($decision) ? $decision : Decision::MONITOR);

        return match ($value) {
            Decision::ALLOW, Decision::MONITOR, Decision::BLOCK, Decision::CHALLENGE => $value,
            default => Decision::MONITOR,
        };
    }
}
