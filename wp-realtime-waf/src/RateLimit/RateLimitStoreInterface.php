<?php

namespace WPRTWAF\RateLimit;

interface RateLimitStoreInterface
{
    public function increment(string $key, int $window, int $now): int;
}
