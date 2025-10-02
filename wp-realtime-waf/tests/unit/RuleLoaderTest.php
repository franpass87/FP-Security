<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Actions\Decision;
use WPRTWAF\Rules\RuleLoader;

class RuleLoaderTest extends TestCase
{
    public function testLoadsRulesFromJsonFiles(): void
    {
        $dir = sys_get_temp_dir() . '/wprtwaf-rules-' . uniqid();
        mkdir($dir);

        $ruleData = [
            [
                'id' => 'temp-rule',
                'pattern' => '/test/i',
                'targets' => ['all'],
                'action' => Decision::BLOCK,
            ],
        ];

        file_put_contents($dir . '/rule.json', json_encode($ruleData, JSON_PRETTY_PRINT));

        $loader = new RuleLoader($dir);
        $rules = $loader->load();

        $this->assertCount(1, $rules);
        $this->assertSame('temp-rule', $rules[0]['id']);

        array_map('unlink', glob($dir . '/*.json') ?: []);
        rmdir($dir);
    }

    public function testNormalizesSeverityEnabledAndTags(): void
    {
        $dir = sys_get_temp_dir() . '/wprtwaf-rules-' . uniqid();
        mkdir($dir);

        $ruleData = [
            'id' => 'normalize-rule',
            'pattern' => 'select',
            'severity' => 'CRITICAL',
            'enabled' => '0',
            'tags' => 'SQLI',
        ];

        file_put_contents($dir . '/normalize.json', json_encode($ruleData, JSON_PRETTY_PRINT));

        $loader = new RuleLoader($dir);
        $rules = $loader->load();

        $this->assertCount(1, $rules);
        $this->assertSame('critical', $rules[0]['severity']);
        $this->assertFalse($rules[0]['enabled']);
        $this->assertSame(['sqli'], $rules[0]['tags']);

        array_map('unlink', glob($dir . '/*.json') ?: []);
        rmdir($dir);
    }

    public function testBuiltinRulesProvideSeverityAndEnabledFlags(): void
    {
        $dir = dirname(__DIR__, 2) . '/rules/builtin';

        $loader = new RuleLoader($dir);
        $rules = $loader->load();

        $this->assertNotEmpty($rules, 'Expected builtin rules to be present.');

        foreach ($rules as $rule) {
            $this->assertArrayHasKey('severity', $rule);
            $this->assertContains($rule['severity'], ['low', 'medium', 'high', 'critical']);
            $this->assertArrayHasKey('enabled', $rule);
            $this->assertIsBool($rule['enabled']);
        }
    }
}
