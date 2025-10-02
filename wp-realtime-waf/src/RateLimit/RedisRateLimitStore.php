<?php

namespace WPRTWAF\RateLimit;

use InvalidArgumentException;
use Predis\ClientInterface;
use RuntimeException;

class RedisRateLimitStore implements RateLimitStoreInterface
{
    /**
     * @var ClientInterface|object
     */
    private readonly object $client;

    /**
     * @param ClientInterface|object $client
     */
    public function __construct(object $client)
    {
        foreach (['zadd', 'zremrangebyscore', 'zcard', 'expire'] as $method) {
            if (!method_exists($client, $method)) {
                throw new InvalidArgumentException('Redis client must implement method ' . $method);
            }
        }

        $this->client = $client;
    }

    public function increment(string $key, int $window, int $now): int
    {
        $this->pruneWindow($key, $window, $now);
        $member = $this->createMember($now);

        $this->client->zadd($key, [$member => $now]);
        $count = (int) $this->client->zcard($key);
        $this->client->expire($key, $window + 5);

        return $count;
    }

    private function pruneWindow(string $key, int $window, int $now): void
    {
        $min = max(0, $now - $window);
        $this->client->zremrangebyscore($key, 0, $min);
    }

    private function createMember(int $now): string
    {
        try {
            return sprintf('%d.%s', $now, bin2hex(random_bytes(6)));
        } catch (\Throwable $e) {
            throw new RuntimeException('Failed to generate rate limit member identifier.', 0, $e);
        }
    }
}
