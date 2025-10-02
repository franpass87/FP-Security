<?php

namespace WPRTWAF\Integrity;

class OptionsBaselineStore implements BaselineStoreInterface
{
    private const OPTION_KEY = 'wp_realtime_waf_file_baseline';
    private const QUARANTINE_KEY = 'wp_realtime_waf_quarantine';

    /**
     * @var array{generated_at?: int, files?: array<string, array{hash: string, size: int, mtime: int}>}
     */
    private static array $baselineMemory = [];

    /**
     * @var array<string, array{flagged_at: int, reason: string}>
     */
    private static array $quarantineMemory = [];

    public function loadBaseline(): array
    {
        if (function_exists('get_option')) {
            $stored = get_option(self::OPTION_KEY, []);
            if (is_array($stored)) {
                return $stored;
            }

            return [];
        }

        return self::$baselineMemory;
    }

    public function saveBaseline(array $baseline): void
    {
        if (function_exists('update_option')) {
            update_option(self::OPTION_KEY, $baseline, false);
            return;
        }

        self::$baselineMemory = $baseline;
    }

    public function loadQuarantine(): array
    {
        if (function_exists('get_option')) {
            $stored = get_option(self::QUARANTINE_KEY, []);
            if (is_array($stored)) {
                return $stored;
            }

            return [];
        }

        return self::$quarantineMemory;
    }

    public function saveQuarantine(array $records): void
    {
        if (function_exists('update_option')) {
            update_option(self::QUARANTINE_KEY, $records, false);
            return;
        }

        self::$quarantineMemory = $records;
    }
}
