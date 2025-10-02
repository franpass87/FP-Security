<?php

namespace {
    if (!function_exists('is_user_logged_in')) {
        function is_user_logged_in(): bool
        {
            return (bool) ($GLOBALS['wprtwaf_is_user_logged_in'] ?? false);
        }
    }

    if (!function_exists('wp_verify_nonce')) {
        function wp_verify_nonce(string $nonce, string $action)
        {
            return $nonce === 'valid';
        }
    }
}

namespace WPRTWAF\Tests\Unit {

use PHPUnit\Framework\TestCase;
use RuntimeException;
use WPRTWAF\Auth\RestGuard;

class RestGuardTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $GLOBALS['wprtwaf_is_user_logged_in'] = false;
    }

    public function testAllowsWhenDisabled(): void
    {
        $guard = new RestGuard(static fn (): array => ['auth' => ['rest' => ['enabled' => false]]]);

        $request = new RestRequestStub('/wp/v2/posts', 'GET');
        $result = $guard->enforce(null, null, $request);

        $this->assertNull($result);
    }

    public function testBlocksWhenNonceMissing(): void
    {
        $guard = new RestGuard(static fn (): array => [
            'auth' => [
                'rest' => [
                    'enabled' => true,
                    'allow_anonymous' => false,
                    'require_nonce' => true,
                    'message' => 'Restricted',
                    'allow_routes' => [],
                ],
            ],
        ]);

        $request = new RestRequestStub('/wp/v2/posts', 'POST');

        $result = $guard->enforce(null, null, $request);

        $this->assertInstanceOf(RuntimeException::class, $result);
        $this->assertSame('Restricted', $result->getMessage());
    }

    public function testAllowsAnonWithValidNonce(): void
    {
        $guard = new RestGuard(static fn (): array => [
            'auth' => [
                'rest' => [
                    'enabled' => true,
                    'allow_anonymous' => true,
                    'require_nonce' => true,
                    'message' => 'Restricted',
                    'allow_routes' => [],
                ],
            ],
        ]);

        $request = new RestRequestStub('/wp/v2/posts', 'POST', ['X-WP-Nonce' => 'valid']);

        $result = $guard->enforce(null, null, $request);

        $this->assertNull($result);
    }

    public function testAllowsWhitelistedRoute(): void
    {
        $guard = new RestGuard(static fn (): array => [
            'auth' => [
                'rest' => [
                    'enabled' => true,
                    'allow_anonymous' => false,
                    'require_nonce' => false,
                    'message' => 'Restricted',
                    'allow_routes' => ['/public/*'],
                ],
            ],
        ]);

        $request = new RestRequestStub('/public/data', 'GET');

        $result = $guard->enforce(null, null, $request);

        $this->assertNull($result);
    }
}

class RestRequestStub
{
    public function __construct(
        private string $route,
        private string $method,
        private array $headers = []
    ) {
    }

    public function get_route(): string
    {
        return $this->route;
    }

    public function get_method(): string
    {
        return $this->method;
    }

    public function get_header(string $name): string
    {
        return $this->headers[$name] ?? '';
    }
}

}
