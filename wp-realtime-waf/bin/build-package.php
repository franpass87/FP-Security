#!/usr/bin/env php
<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This script must be executed from the command line." . PHP_EOL);
    exit(1);
}

if (!class_exists(ZipArchive::class)) {
    fwrite(STDERR, "ZipArchive extension is required to build the package." . PHP_EOL);
    exit(1);
}

$root = dirname(__DIR__);
$manifestPath = $root . '/plugin-manifest.json';
if (!is_file($manifestPath)) {
    fwrite(STDERR, "Unable to locate plugin-manifest.json" . PHP_EOL);
    exit(1);
}

$manifest = json_decode((string) file_get_contents($manifestPath), true);
if (!is_array($manifest)) {
    fwrite(STDERR, "Invalid plugin-manifest.json" . PHP_EOL);
    exit(1);
}

$version = isset($manifest['version']) && is_string($manifest['version']) ? $manifest['version'] : 'dev';
$buildRoot = $root . '/build/package';
$packageRoot = $buildRoot . '/wp-realtime-waf';
$distDir = $root . '/dist';

removePath($buildRoot);
removePath($distDir);

mkdir($packageRoot, 0775, true);
mkdir($distDir, 0775, true);

$includePaths = [
    'wp-realtime-waf.php',
    'mu-loader.php',
    'src',
    'rules',
    'assets',
    'views',
    'vendor',
    'composer.json',
    'composer.lock',
    'plugin-manifest.json',
    'README.md',
    'CHANGELOG.md',
    'docs',
];

foreach ($includePaths as $path) {
    $source = $root . '/' . $path;
    if (!file_exists($source)) {
        continue;
    }

    copyPath($source, $packageRoot . '/' . $path);
}

pruneDevDependencies($packageRoot);

$zipPath = sprintf('%s/wp-realtime-waf-%s.zip', $distDir, $version);
if (file_exists($zipPath)) {
    unlink($zipPath);
}

$zip = new ZipArchive();
if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    fwrite(STDERR, "Unable to open zip archive for writing: $zipPath" . PHP_EOL);
    exit(1);
}

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($packageRoot, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::LEAVES_ONLY
);

$packageRootLength = strlen($packageRoot) + 1;
foreach ($iterator as $file) {
    /** @var SplFileInfo $file */
    if ($file->isDir()) {
        continue;
    }

    $absolutePath = $file->getPathname();
    $relativePath = substr($absolutePath, $packageRootLength);
    $zip->addFile($absolutePath, 'wp-realtime-waf/' . str_replace('\\', '/', $relativePath));
}

$zip->close();

echo sprintf("Package created at %s\n", $zipPath);

return 0;

/**
 * Recursively remove a file or directory.
 */
function removePath(string $path): void
{
    if (!file_exists($path)) {
        return;
    }

    if (is_file($path) || is_link($path)) {
        @unlink($path);

        return;
    }

    $items = new FilesystemIterator($path, FilesystemIterator::SKIP_DOTS);
    foreach ($items as $item) {
        removePath($item->getPathname());
    }

    @rmdir($path);
}

/**
 * Copy a file or directory recursively.
 */
function copyPath(string $source, string $destination): void
{
    if (is_dir($source) && !is_link($source)) {
        if (!is_dir($destination)) {
            mkdir($destination, 0775, true);
        }

        $items = new FilesystemIterator($source, FilesystemIterator::SKIP_DOTS);
        foreach ($items as $item) {
            copyPath($item->getPathname(), $destination . '/' . $item->getBasename());
        }

        return;
    }

    $parent = dirname($destination);
    if (!is_dir($parent)) {
        mkdir($parent, 0775, true);
    }

    copy($source, $destination);
}

function pruneDevDependencies(string $packageRoot): void
{
    $lockPath = $packageRoot . '/composer.lock';
    if (!is_file($lockPath)) {
        return;
    }

    $lock = json_decode((string) file_get_contents($lockPath), true);
    if (!is_array($lock) || !isset($lock['packages-dev']) || !is_array($lock['packages-dev'])) {
        return;
    }

    foreach ($lock['packages-dev'] as $package) {
        if (!is_array($package) || !isset($package['name'])) {
            continue;
        }

        $path = $packageRoot . '/vendor/' . str_replace('/', DIRECTORY_SEPARATOR, (string) $package['name']);
        removePath($path);
    }

    $binDir = $packageRoot . '/vendor/bin';
    if (is_dir($binDir)) {
        $items = new FilesystemIterator($binDir, FilesystemIterator::SKIP_DOTS);
        foreach ($items as $item) {
            removePath($item->getPathname());
        }

        @rmdir($binDir);
    }
}
