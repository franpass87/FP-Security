<?php

namespace WPRTWAF\Integrity;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

class FileMonitor
{
    /**
     * @param callable(): array $optionsProvider
     * @param callable(): array<string, string> $pathsProvider
     */
    public function __construct(
        private readonly BaselineStoreInterface $baselineStore,
        private readonly MalwareScanner $malwareScanner,
        private $optionsProvider,
        private $pathsProvider = null
    ) {
        if ($this->pathsProvider === null) {
            $this->pathsProvider = [$this, 'defaultPaths'];
        }
    }

    public function register(): void
    {
        if (!function_exists('add_action')) {
            return;
        }

        add_action('wp_realtime_waf_integrity_build_baseline', [$this, 'buildBaseline']);
        add_action('wp_realtime_waf_integrity_scan', [$this, 'scanForChanges']);
        add_action('wp_realtime_waf_integrity_malware_scan', [$this, 'scanForMalware']);
    }

    public function maybePrimeBaseline(): void
    {
        if (!$this->isIntegrityEnabled()) {
            return;
        }

        $baseline = $this->baselineStore->loadBaseline();
        if (!empty($baseline['files'])) {
            return;
        }

        if ($this->shouldAutoBuild() && function_exists('wp_schedule_single_event') && function_exists('wp_next_scheduled')) {
            if (!wp_next_scheduled('wp_realtime_waf_integrity_build_baseline')) {
                wp_schedule_single_event(time() + 60, 'wp_realtime_waf_integrity_build_baseline');
            }

            return;
        }

        if ($this->shouldAutoBuild()) {
            $this->buildBaseline();
        }
    }

    /**
     * @return array{generated_at: int, files: array<string, array{hash: string, size: int, mtime: int}>}
     */
    public function buildBaseline(): array
    {
        if (!$this->isIntegrityEnabled()) {
            $baseline = ['generated_at' => time(), 'files' => []];
            $this->baselineStore->saveBaseline($baseline);

            return $baseline;
        }

        $files = $this->snapshotFiles();
        $baseline = [
            'generated_at' => time(),
            'files' => $files,
        ];

        $this->baselineStore->saveBaseline($baseline);

        return $baseline;
    }

    public function scanForChanges(): IntegrityReport
    {
        $baseline = $this->baselineStore->loadBaseline();
        $existing = is_array($baseline['files'] ?? null) ? $baseline['files'] : [];
        $current = $this->snapshotFiles();
        $added = [];
        $removed = [];
        $modified = [];

        foreach ($current as $path => $info) {
            if (!isset($existing[$path])) {
                $added[] = $path;
                continue;
            }

            if ($existing[$path]['hash'] !== $info['hash']) {
                $modified[] = $path;
            }
        }

        foreach ($existing as $path => $info) {
            if (!isset($current[$path])) {
                $removed[] = $path;
            }
        }

        $quarantine = array_keys($this->baselineStore->loadQuarantine());

        return new IntegrityReport(
            $added,
            $removed,
            $modified,
            $quarantine,
            (int) ($baseline['generated_at'] ?? 0),
            time()
        );
    }

    public function scanForMalware(): MalwareScanResult
    {
        if (!$this->isMalwareScanEnabled()) {
            return new MalwareScanResult([], time());
        }

        $paths = array_values($this->resolvePaths());
        $result = $this->malwareScanner->scanPaths($paths);

        if ($result->hasFindings() && $this->shouldQuarantine()) {
            $records = $this->baselineStore->loadQuarantine();
            $now = time();

            foreach ($result->getMatches() as $match) {
                $key = $this->resolveRelativeFromAbsolute($match->path);
                $records[$key] = [
                    'flagged_at' => $now,
                    'reason' => $match->description,
                ];
            }

            $this->baselineStore->saveQuarantine($records);
        }

        return $result;
    }

    public function clearQuarantine(string $path): void
    {
        $records = $this->baselineStore->loadQuarantine();
        $key = $this->resolveRelativeFromAbsolute($path);
        unset($records[$key]);
        $this->baselineStore->saveQuarantine($records);
    }

    /**
     * @return array<string, array{hash: string, size: int, mtime: int}>
     */
    private function snapshotFiles(): array
    {
        if (!$this->isIntegrityEnabled()) {
            return [];
        }

        $paths = $this->resolvePaths();
        $files = [];

        foreach ($paths as $label => $directory) {
            if (!is_dir($directory)) {
                continue;
            }

            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS)
            );

            /** @var SplFileInfo $file */
            foreach ($iterator as $file) {
                if (!$file->isFile() || !$file->isReadable()) {
                    continue;
                }

                $realPath = $file->getPathname();
                $hash = @hash_file('sha256', $realPath);
                if ($hash === false) {
                    continue;
                }

                $relative = $this->relativePath($label, $directory, $realPath);

                $files[$relative] = [
                    'hash' => $hash,
                    'size' => $file->getSize(),
                    'mtime' => $file->getMTime(),
                ];
            }
        }

        ksort($files);

        return $files;
    }

    private function resolveRelativeFromAbsolute(string $absolute): string
    {
        $absolute = $this->normalizePath($absolute);

        foreach ($this->resolvePaths() as $label => $root) {
            if (str_starts_with($absolute, $root)) {
                $relative = ltrim(substr($absolute, strlen($root)), '/');
                if ($relative === '') {
                    $relative = basename($absolute);
                }

                return $label . '/' . $relative;
            }
        }

        return $absolute;
    }

    /**
     * @return array<string, string>
     */
    private function resolvePaths(): array
    {
        $pathsProvider = $this->pathsProvider;
        $paths = $pathsProvider();

        if (!is_array($paths)) {
            return [];
        }

        $options = ($this->optionsProvider)();
        $integrity = $options['integrity'] ?? [];

        $includeCore = !array_key_exists('include_core', $integrity) || !empty($integrity['include_core']);
        $includePlugins = !array_key_exists('include_plugins', $integrity) || !empty($integrity['include_plugins']);
        $includeThemes = !array_key_exists('include_themes', $integrity) || !empty($integrity['include_themes']);

        $resolved = [];

        foreach ($paths as $label => $path) {
            if (!is_string($label) || $label === '') {
                continue;
            }

            if (!is_string($path) || $path === '') {
                continue;
            }

            if (($label === 'core' && !$includeCore) || ($label === 'plugins' && !$includePlugins) || ($label === 'themes' && !$includeThemes)) {
                continue;
            }

            $normalized = $this->normalizePath($path);
            if ($normalized === '') {
                continue;
            }

            $resolved[$label] = $normalized;
        }

        return $resolved;
    }

    private function normalizePath(string $path): string
    {
        $path = str_replace(['\\\\', '\\'], '/', $path);
        return rtrim($path, '/');
    }

    private function relativePath(string $label, string $root, string $absolute): string
    {
        $root = $this->normalizePath($root);
        $absolute = $this->normalizePath($absolute);

        if (str_starts_with($absolute, $root)) {
            $relative = ltrim(substr($absolute, strlen($root)), '/');
        } else {
            $relative = basename($absolute);
        }

        if ($relative === '') {
            $relative = basename($absolute);
        }

        return $label . '/' . $relative;
    }

    private function isIntegrityEnabled(): bool
    {
        $options = ($this->optionsProvider)();
        $integrity = $options['integrity'] ?? [];

        return !empty($integrity['enabled']);
    }

    private function shouldAutoBuild(): bool
    {
        $options = ($this->optionsProvider)();
        $integrity = $options['integrity'] ?? [];

        return !empty($integrity['auto_build']);
    }

    private function shouldQuarantine(): bool
    {
        $options = ($this->optionsProvider)();
        $integrity = $options['integrity'] ?? [];

        return !empty($integrity['quarantine']);
    }

    private function isMalwareScanEnabled(): bool
    {
        $options = ($this->optionsProvider)();
        $integrity = $options['integrity']['malware_scan'] ?? [];

        return !empty($integrity['enabled']);
    }

    /**
     * @return array<string, string>
     */
    private function defaultPaths(): array
    {
        $paths = [];

        if (defined('ABSPATH')) {
            $paths['core'] = (string) ABSPATH;
        }

        if (defined('WP_CONTENT_DIR')) {
            $content = (string) WP_CONTENT_DIR;

            $plugins = $content . '/plugins';
            if (is_dir($plugins)) {
                $paths['plugins'] = $plugins;
            }

            $themes = $content . '/themes';
            if (is_dir($themes)) {
                $paths['themes'] = $themes;
            }
        }

        if ($paths === []) {
            $paths['plugin'] = dirname(__DIR__, 2);
        }

        return $paths;
    }
}
