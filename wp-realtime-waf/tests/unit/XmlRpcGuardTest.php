<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Auth\XmlRpcGuard;

class XmlRpcGuardTest extends TestCase
{
    public function testDisableAllTurnsOffXmlRpc(): void
    {
        $guard = new XmlRpcGuard(static fn (): array => [
            'auth' => [
                'xmlrpc' => [
                    'enabled' => true,
                    'disable_all' => true,
                    'allow_methods' => ['demo.sayHello'],
                    'block_methods' => [],
                ],
            ],
        ]);

        $this->assertFalse($guard->filterEnabled(true));
    }

    public function testAllowListWhenDisabled(): void
    {
        $guard = new XmlRpcGuard(static fn (): array => [
            'auth' => [
                'xmlrpc' => [
                    'enabled' => true,
                    'disable_all' => true,
                    'allow_methods' => ['demo.sayHello'],
                    'block_methods' => [],
                ],
            ],
        ]);

        $methods = [
            'demo.sayHello' => 'demo.sayHello',
            'demo.addTwoNumbers' => 'demo.addTwoNumbers',
        ];

        $filtered = $guard->filterMethods($methods);

        $this->assertSame(['demo.sayHello' => 'demo.sayHello'], $filtered);
    }

    public function testBlocksSpecificMethods(): void
    {
        $guard = new XmlRpcGuard(static fn (): array => [
            'auth' => [
                'xmlrpc' => [
                    'enabled' => true,
                    'disable_all' => false,
                    'allow_methods' => [],
                    'block_methods' => ['pingback.ping'],
                ],
            ],
        ]);

        $methods = [
            'pingback.ping' => 'pingback.ping',
            'demo.sayHello' => 'demo.sayHello',
        ];

        $filtered = $guard->filterMethods($methods);

        $this->assertSame(['demo.sayHello' => 'demo.sayHello'], $filtered);
    }
}
