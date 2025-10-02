<?php

namespace WPRTWAF\Logging;

use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

class LoggerFactory
{
    /** @var array<string, LoggerInterface> */
    private array $loggers = [];

    public function create(string $channel = 'waf'): LoggerInterface
    {
        if (isset($this->loggers[$channel])) {
            return $this->loggers[$channel];
        }

        if (!class_exists(Logger::class)) {
            return $this->loggers[$channel] = new NullLogger();
        }

        $logger = new Logger($channel);
        $path = $this->resolveLogPath($channel);

        try {
            $handler = new StreamHandler($path, Logger::INFO);
            $logger->pushHandler($handler);
        } catch (\Throwable $e) {
            return $this->loggers[$channel] = new NullLogger();
        }

        return $this->loggers[$channel] = $logger;
    }

    private function resolveLogPath(string $channel): string
    {
        $filename = 'wp-realtime-waf-' . preg_replace('/[^a-z0-9\-]+/i', '-', $channel) . '.log';

        if (function_exists('wp_upload_dir')) {
            $uploads = wp_upload_dir();
            if (is_array($uploads) && isset($uploads['basedir'])) {
                $dir = rtrim((string) $uploads['basedir'], '/\\') . '/wp-realtime-waf';
                if (!is_dir($dir)) {
                    @mkdir($dir, 0755, true);
                }

                if (is_dir($dir) && is_writable($dir)) {
                    return $dir . '/' . $filename;
                }
            }
        }

        $dir = sys_get_temp_dir();
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        return rtrim($dir, '/\\') . '/' . $filename;
    }
}
