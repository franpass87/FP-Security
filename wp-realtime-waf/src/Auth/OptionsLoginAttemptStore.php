<?php

namespace WPRTWAF\Auth;

class OptionsLoginAttemptStore implements LoginAttemptStoreInterface
{
    private const OPTION_KEY = 'wp_realtime_waf_login_limits';

    /**
     * @var array{attempts: array<string, array<int>>, locks: array<string, int>}
     */
    private array $data = [
        'attempts' => [],
        'locks' => [],
    ];

    private bool $loaded = false;

    private bool $dirty = false;

    /**
     * @var array{attempts: array<string, array<int>>, locks: array<string, int>}
     */
    private static array $memoryStore = [
        'attempts' => [],
        'locks' => [],
    ];

    public function __destruct()
    {
        $this->persist();
    }

    public function recordAttempt(string $key, int $window, int $now): int
    {
        $this->load($now);

        $events = $this->data['attempts'][$key] ?? [];
        $threshold = $now - $window;
        $filtered = [];

        foreach ($events as $timestamp) {
            $timestamp = (int) $timestamp;
            if ($timestamp > $threshold) {
                $filtered[] = $timestamp;
            }
        }

        $filtered[] = $now;
        $this->data['attempts'][$key] = $filtered;
        $this->dirty = true;

        return count($filtered);
    }

    public function clearAttempts(string $key): void
    {
        $this->load(time());

        unset($this->data['attempts'][$key], $this->data['locks'][$key]);
        $this->dirty = true;
    }

    public function isLocked(string $key, int $now): bool
    {
        $this->load($now);

        $expires = (int) ($this->data['locks'][$key] ?? 0);
        if ($expires <= $now) {
            unset($this->data['locks'][$key]);
            if ($expires !== 0) {
                $this->dirty = true;
            }

            return false;
        }

        return true;
    }

    public function lock(string $key, int $duration, int $now): void
    {
        $this->load($now);

        $this->data['locks'][$key] = $now + max(1, $duration);
        $this->dirty = true;
    }

    private function load(int $now): void
    {
        if ($this->loaded) {
            return;
        }

        $stored = $this->loadOption();
        if (!is_array($stored)) {
            $stored = ['attempts' => [], 'locks' => []];
        }

        $attempts = $stored['attempts'] ?? [];
        $locks = $stored['locks'] ?? [];

        if (!is_array($attempts)) {
            $attempts = [];
        }

        if (!is_array($locks)) {
            $locks = [];
        }

        foreach ($locks as $key => $expires) {
            if ((int) $expires <= $now) {
                unset($locks[$key]);
            } else {
                $locks[$key] = (int) $expires;
            }
        }

        $this->data = [
            'attempts' => [],
            'locks' => $locks,
        ];

        foreach ($attempts as $key => $events) {
            if (!is_array($events)) {
                continue;
            }

            $filtered = [];
            foreach ($events as $timestamp) {
                $timestamp = (int) $timestamp;
                if ($timestamp > 0) {
                    $filtered[] = $timestamp;
                }
            }

            if ($filtered !== []) {
                $this->data['attempts'][$key] = $filtered;
            }
        }

        $this->loaded = true;
    }

    private function persist(): void
    {
        if (!$this->dirty) {
            return;
        }

        $now = time();
        foreach ($this->data['attempts'] as $key => $events) {
            $filtered = [];
            foreach ($events as $timestamp) {
                $timestamp = (int) $timestamp;
                if ($timestamp > 0) {
                    $filtered[] = $timestamp;
                }
            }

            if ($filtered === []) {
                unset($this->data['attempts'][$key]);
            } else {
                $this->data['attempts'][$key] = $filtered;
            }
        }

        foreach ($this->data['locks'] as $key => $expires) {
            if ((int) $expires <= $now) {
                unset($this->data['locks'][$key]);
            }
        }

        $payload = $this->data;

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
            return get_option(self::OPTION_KEY, ['attempts' => [], 'locks' => []]);
        }

        return self::$memoryStore;
    }
}
