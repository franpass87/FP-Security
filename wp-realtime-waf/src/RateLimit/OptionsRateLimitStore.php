<?php

namespace WPRTWAF\RateLimit;

class OptionsRateLimitStore implements RateLimitStoreInterface
{
    private const OPTION_KEY = 'wp_realtime_waf_rate_limits';

    /**
     * @var array{buckets: array<string, array{events: array<int>, expires: int}>}
     */
    private array $data = ['buckets' => []];

    private bool $loaded = false;

    private bool $dirty = false;

    /**
     * @var array{buckets: array<string, array{events: array<int>, expires: int}>}
     */
    private static array $memoryStore = ['buckets' => []];

    public function __destruct()
    {
        $this->persist();
    }

    public function increment(string $key, int $window, int $now): int
    {
        $this->load($now);

        $bucket = $this->data['buckets'][$key] ?? ['events' => [], 'expires' => $now + $window];

        $threshold = $now - $window;
        $events = [];

        foreach ($bucket['events'] as $timestamp) {
            if ($timestamp > $threshold) {
                $events[] = $timestamp;
            }
        }

        $events[] = $now;

        $this->data['buckets'][$key] = [
            'events' => $events,
            'expires' => $now + $window,
        ];

        $this->dirty = true;

        return count($events);
    }

    public function flush(): void
    {
        $this->persist();
    }

    private function load(int $now): void
    {
        if ($this->loaded) {
            return;
        }

        $stored = $this->loadOption();
        if (!is_array($stored) || !isset($stored['buckets']) || !is_array($stored['buckets'])) {
            $stored = ['buckets' => []];
        }

        $this->data['buckets'] = [];

        foreach ($stored['buckets'] as $bucketKey => $bucketData) {
            if (!is_array($bucketData)) {
                continue;
            }

            $expires = (int) ($bucketData['expires'] ?? 0);
            if ($expires <= $now) {
                continue;
            }

            $events = [];
            if (isset($bucketData['events']) && is_array($bucketData['events'])) {
                foreach ($bucketData['events'] as $timestamp) {
                    $timestamp = (int) $timestamp;
                    if ($timestamp > 0) {
                        $events[] = $timestamp;
                    }
                }
            }

            $this->data['buckets'][$bucketKey] = [
                'events' => $events,
                'expires' => $expires,
            ];
        }

        $this->loaded = true;
    }

    private function persist(): void
    {
        if (!$this->dirty) {
            return;
        }

        $now = time();

        foreach ($this->data['buckets'] as $key => $bucket) {
            if (($bucket['expires'] ?? 0) <= $now) {
                unset($this->data['buckets'][$key]);
            }
        }

        $payload = ['buckets' => $this->data['buckets']];

        if (function_exists('update_option')) {
            update_option(self::OPTION_KEY, $payload, false);
        } else {
            self::$memoryStore = $payload;
        }

        $this->dirty = false;
    }

    private function loadOption(): mixed
    {
        if (function_exists('get_option')) {
            return get_option(self::OPTION_KEY, ['buckets' => []]);
        }

        return self::$memoryStore;
    }
}
