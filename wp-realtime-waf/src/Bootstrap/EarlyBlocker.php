<?php

namespace WPRTWAF\Bootstrap;

class EarlyBlocker
{
    private const DISABLE_OPTION = 'wp_realtime_waf_disable_until';

    public function register(): void
    {
        if (function_exists('add_action')) {
            add_action('muplugins_loaded', [$this, 'maybeBlock'], 0);
            add_action('plugins_loaded', [$this, 'maybeBlock'], -9999);
        } else {
            $this->maybeBlock();
        }
    }

    public function maybeBlock(): void
    {
        if (!$this->isActive()) {
            return;
        }

        $payload = $this->unslash($_SERVER['REQUEST_URI'] ?? '');
        $body = $this->getRawInput();

        if ($this->containsTestSignature($payload) || $this->containsTestSignature($body)) {
            $this->terminate();
        }
    }

    private function isActive(): bool
    {
        if (defined('WP_REALTIME_WAF_DISABLE_UNTIL') && time() < (int) WP_REALTIME_WAF_DISABLE_UNTIL) {
            return false;
        }

        $disabledUntil = $this->getSiteOption(self::DISABLE_OPTION);
        if ($disabledUntil && time() < (int) $disabledUntil) {
            return false;
        }

        return strtoupper((string) WP_REALTIME_WAF_MODE) === 'BLOCK';
    }

    private function getRawInput(): string
    {
        $body = file_get_contents('php://input');
        return is_string($body) ? $body : '';
    }

    private function containsTestSignature(string $value): bool
    {
        return str_contains($value, '__TEST_SUSPECT__');
    }

    private function unslash(string $value): string
    {
        if (function_exists('wp_unslash')) {
            return wp_unslash($value);
        }

        return stripslashes($value);
    }

    private function getSiteOption(string $key): mixed
    {
        if (function_exists('get_site_option')) {
            return get_site_option($key);
        }

        return null;
    }

    private function terminate(): never
    {
        $message = $this->translate('Forbidden');
        if (function_exists('wp_die')) {
            wp_die($message, $message, ['response' => 403]);
        }

        throw new \RuntimeException($message, 403);
    }

    private function translate(string $text): string
    {
        if (function_exists('__')) {
            return __($text, 'wp-realtime-waf');
        }

        return $text;
    }
}
