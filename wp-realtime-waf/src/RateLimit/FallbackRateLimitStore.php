<?php

namespace WPRTWAF\RateLimit;

use Throwable;

class FallbackRateLimitStore implements RateLimitStoreInterface
{
    private bool $primaryHealthy = true;

    public function __construct(
        private readonly RateLimitStoreInterface $primary,
        private readonly RateLimitStoreInterface $fallback
    ) {
    }

    public function increment(string $key, int $window, int $now): int
    {
        if ($this->primaryHealthy) {
            try {
                return $this->primary->increment($key, $window, $now);
            } catch (Throwable $exception) {
                $this->primaryHealthy = false;
            }
        }

        return $this->fallback->increment($key, $window, $now);
    }
}
