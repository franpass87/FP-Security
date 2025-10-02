<?php

namespace WPRTWAF\Tests\Unit;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use WPRTWAF\Bootstrap\ServiceContainer;

class ServiceContainerTest extends TestCase
{
    public function testSharedServiceReturnsSameInstance(): void
    {
        $container = new ServiceContainer();
        $container->share('foo', static fn (ServiceContainer $c): \stdClass => new \stdClass());

        $first = $container->get('foo');
        $second = $container->get('foo');

        $this->assertSame($first, $second);
    }

    public function testFactoryServiceReturnsNewInstance(): void
    {
        $container = new ServiceContainer();
        $container->factory('foo', static fn (ServiceContainer $c): \stdClass => new \stdClass());

        $first = $container->get('foo');
        $second = $container->get('foo');

        $this->assertNotSame($first, $second);
    }

    public function testMissingServiceThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $container = new ServiceContainer();
        $container->get('missing');
    }
}
