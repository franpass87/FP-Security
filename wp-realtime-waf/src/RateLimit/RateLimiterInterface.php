<?php

namespace WPRTWAF\RateLimit;

use WPRTWAF\Http\NormalizedRequest;

interface RateLimiterInterface
{
    public function allow(NormalizedRequest $request): bool;
}
