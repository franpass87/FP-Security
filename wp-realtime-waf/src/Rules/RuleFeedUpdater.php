<?php

namespace WPRTWAF\Rules;

use JsonException;

class RuleFeedUpdater
{
    private const OPTION_KEY = 'wp_realtime_waf_rule_feed_state';

    /** @var callable */
    private $getOption;

    /** @var callable */
    private $updateOption;

    /** @var callable */
    private $timeProvider;

    public function __construct(
        private readonly RuleRepository $repository,
        private readonly string $feedPath,
        private readonly string $sharedSecret,
        ?callable $getOption = null,
        ?callable $updateOption = null,
        ?callable $timeProvider = null
    ) {
        $this->getOption = $getOption ?? static function (string $key, mixed $default): mixed {
            if (function_exists('get_option')) {
                return get_option($key, $default);
            }

            return $default;
        };

        $this->updateOption = $updateOption ?? static function (string $key, array $value): void {
            if (function_exists('update_option')) {
                update_option($key, $value);
            }
        };

        $this->timeProvider = $timeProvider ?? static fn (): int => time();
    }

    public function maybeUpdate(): void
    {
        $state = $this->loadState();
        if (isset($state['rules']) && is_array($state['rules'])) {
            $this->repository->setFeedRules($state['rules']);
        }

        $feed = $this->readFeed();
        if ($feed === null) {
            return;
        }

        [$payload, $signature] = $feed;

        $encodedPayload = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($encodedPayload)) {
            return;
        }

        $hash = hash('sha256', $encodedPayload);
        $expectedSignature = hash_hmac('sha256', $encodedPayload, $this->sharedSecret);
        if (!hash_equals($expectedSignature, $signature)) {
            return;
        }

        if ($this->isExpired($payload)) {
            return;
        }

        $now = ($this->timeProvider)();

        if (isset($state['hash']) && is_string($state['hash']) && hash_equals($state['hash'], $hash)) {
            $state['last_checked'] = $now;
            $this->persistState($state);

            return;
        }

        $rules = $payload['rules'] ?? [];
        if (!is_array($rules)) {
            $rules = [];
        }

        $this->repository->setFeedRules($rules);

        $state = [
            'version' => isset($payload['version']) && is_string($payload['version']) ? $payload['version'] : 'unknown',
            'hash' => $hash,
            'signature' => $signature,
            'updated_at' => $now,
            'last_checked' => $now,
            'rules' => $this->repository->getFeedRules(),
        ];

        $this->persistState($state);
    }

    /**
     * @return array{0: array<string, mixed>, 1: string}|null
     */
    private function readFeed(): ?array
    {
        if (!is_file($this->feedPath) || !is_readable($this->feedPath)) {
            return null;
        }

        $contents = @file_get_contents($this->feedPath);
        if (!is_string($contents) || trim($contents) === '') {
            return null;
        }

        try {
            $decoded = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (!is_array($decoded)) {
            return null;
        }

        $payload = $decoded['payload'] ?? null;
        $signature = $decoded['signature'] ?? null;
        $algorithm = isset($decoded['algorithm']) && is_string($decoded['algorithm']) ? strtolower($decoded['algorithm']) : 'sha256';

        if ($algorithm !== 'sha256' || !is_array($payload) || !is_string($signature) || $signature === '') {
            return null;
        }

        return [$payload, $signature];
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function isExpired(array $payload): bool
    {
        $expiresAt = $payload['expires_at'] ?? null;
        if (!is_string($expiresAt) || $expiresAt === '') {
            return false;
        }

        $timestamp = strtotime($expiresAt);
        if ($timestamp === false) {
            return false;
        }

        return $timestamp < ($this->timeProvider)();
    }

    /**
     * @return array<string, mixed>
     */
    private function loadState(): array
    {
        $raw = ($this->getOption)(self::OPTION_KEY, []);
        if (!is_array($raw)) {
            return [];
        }

        return $raw;
    }

    /**
     * @param array<string, mixed> $state
     */
    private function persistState(array $state): void
    {
        ($this->updateOption)(self::OPTION_KEY, $state);
    }
}
