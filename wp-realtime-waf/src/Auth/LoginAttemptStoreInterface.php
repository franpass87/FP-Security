<?php

namespace WPRTWAF\Auth;

interface LoginAttemptStoreInterface
{
    public function recordAttempt(string $key, int $window, int $now): int;

    public function clearAttempts(string $key): void;

    public function isLocked(string $key, int $now): bool;

    public function lock(string $key, int $duration, int $now): void;
}
