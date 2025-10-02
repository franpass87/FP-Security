<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Integrity\FileMonitor;
use WPRTWAF\Integrity\InMemoryBaselineStore;
use WPRTWAF\Integrity\MalwareScanner;

class FileMonitorTest extends TestCase
{
    private string $workingDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->workingDir = sys_get_temp_dir() . '/waf-monitor-' . uniqid('', true);
        mkdir($this->workingDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->workingDir);
        parent::tearDown();
    }

    public function testBuildBaselinePersistsHashes(): void
    {
        $coreDir = $this->workingDir . '/core';
        mkdir($coreDir, 0777, true);
        file_put_contents($coreDir . '/index.php', "<?php echo 'ok';\n");

        $store = new InMemoryBaselineStore();
        $monitor = $this->createMonitor($store, ['core' => $coreDir]);

        $baseline = $monitor->buildBaseline();

        $this->assertArrayHasKey('files', $baseline);
        $this->assertArrayHasKey('core/index.php', $baseline['files']);

        $loaded = $store->loadBaseline();
        $this->assertSame($baseline, $loaded);
    }

    public function testScanForChangesDetectsDifferences(): void
    {
        $coreDir = $this->workingDir . '/core';
        mkdir($coreDir, 0777, true);
        file_put_contents($coreDir . '/original.php', "<?php echo 'one';\n");
        file_put_contents($coreDir . '/keep.php', "<?php echo 'keep';\n");

        $store = new InMemoryBaselineStore();
        $monitor = $this->createMonitor($store, ['core' => $coreDir]);
        $monitor->buildBaseline();

        file_put_contents($coreDir . '/original.php', "<?php echo 'changed';\n");
        unlink($coreDir . '/keep.php');
        file_put_contents($coreDir . '/added.php', "<?php echo 'new';\n");

        $report = $monitor->scanForChanges();

        $this->assertContains('core/added.php', $report->getAdded());
        $this->assertContains('core/original.php', $report->getModified());
        $this->assertContains('core/keep.php', $report->getRemoved());
    }

    public function testScanForMalwareFlagsSuspiciousFiles(): void
    {
        $coreDir = $this->workingDir . '/core';
        mkdir($coreDir, 0777, true);
        $suspicious = $coreDir . '/suspicious.php';
        file_put_contents($suspicious, "<?php eval('bad');\n");

        $store = new InMemoryBaselineStore();
        $monitor = $this->createMonitor(
            $store,
            ['core' => $coreDir],
            [
                'integrity' => [
                    'enabled' => true,
                    'auto_build' => false,
                    'quarantine' => true,
                    'include_core' => true,
                    'include_plugins' => true,
                    'include_themes' => true,
                    'malware_scan' => [
                        'enabled' => true,
                        'quarantine' => true,
                    ],
                ],
            ]
        );

        $result = $monitor->scanForMalware();

        $this->assertTrue($result->hasFindings());
        $this->assertNotEmpty($store->loadQuarantine());
        $this->assertArrayHasKey('core/suspicious.php', $store->loadQuarantine());

        $monitor->clearQuarantine($suspicious);
        $this->assertSame([], $store->loadQuarantine());
    }

    private function createMonitor(
        InMemoryBaselineStore $store,
        array $paths,
        ?array $options = null
    ): FileMonitor {
        $options = $options ?? [
            'integrity' => [
                'enabled' => true,
                'auto_build' => false,
                'quarantine' => true,
                'include_core' => true,
                'include_plugins' => true,
                'include_themes' => true,
                'malware_scan' => [
                    'enabled' => false,
                    'quarantine' => true,
                ],
            ],
        ];

        return new FileMonitor(
            $store,
            MalwareScanner::withDefaultPatterns(),
            static fn (): array => $options,
            static fn (): array => $paths
        );
    }

    private function removeDirectory(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }

        $items = scandir($path);
        if (!is_array($items)) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $target = $path . DIRECTORY_SEPARATOR . $item;
            if (is_dir($target)) {
                $this->removeDirectory($target);
            } else {
                @unlink($target);
            }
        }

        @rmdir($path);
    }
}
