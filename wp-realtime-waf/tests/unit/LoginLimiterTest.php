<?php

namespace {
    if (!function_exists('apply_filters')) {
        function apply_filters(string $hook, $value, ...$args)
        {
            if ($hook === 'wp_realtime_waf_two_factor_authenticate') {
                return $GLOBALS['wprtwaf_two_factor_response'] ?? $value;
            }

            return $value;
        }
    }

    if (!function_exists('do_action')) {
        function do_action(string $hook, ...$args): void
        {
            if ($hook === 'wp_realtime_waf_two_factor_challenge') {
                $GLOBALS['wprtwaf_two_factor_action_called'] = true;
            }
        }
    }
}

namespace WPRTWAF\Tests\Unit {

use PHPUnit\Framework\TestCase;
use RuntimeException;
use WPRTWAF\Auth\LoginAttemptStoreInterface;
use WPRTWAF\Auth\LoginLimiter;
use WPRTWAF\Http\ClientIpResolver;

class LoginLimiterTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $_SERVER = ['REMOTE_ADDR' => '198.51.100.5'];
        $GLOBALS['wprtwaf_two_factor_response'] = null;
        $GLOBALS['wprtwaf_two_factor_action_called'] = false;
    }

    public function testLocksAfterThreshold(): void
    {
        $store = new InMemoryLoginAttemptStore();
        $options = $this->options();
        $limiter = $this->createLimiter($store, $options, 100);

        $limiter->recordFailure('admin');
        $limiter->recordFailure('admin');
        $limiter->recordFailure('admin');

        $ipKey = 'wprtwaf:login:ip:' . hash('sha256', '198.51.100.5');
        $this->assertTrue($store->isLocked($ipKey, 100));

        $result = $limiter->enforceLock(null, 'admin', 'password');

        $this->assertInstanceOf(RuntimeException::class, $result);
        $this->assertSame('Locked', $result->getMessage());
    }

    public function testSuccessClearsAttempts(): void
    {
        $store = new InMemoryLoginAttemptStore();
        $options = $this->options();
        $limiter = $this->createLimiter($store, $options, 100);

        $limiter->recordFailure('admin');
        $limiter->recordFailure('admin');
        $limiter->recordSuccess('admin', new \stdClass());

        $this->assertFalse($store->isLocked('wprtwaf:login:ip:' . hash('sha256', '198.51.100.5'), 200));
    }

    public function testTwoFactorFailureBlocks(): void
    {
        $store = new InMemoryLoginAttemptStore();
        $options = $this->options();
        $options['auth']['two_factor']['enabled'] = true;
        $options['auth']['two_factor']['failure_message'] = '2FA required';
        $limiter = $this->createLimiter($store, $options, 100);

        $GLOBALS['wprtwaf_two_factor_response'] = false;

        $result = $limiter->enforceTwoFactor(new \stdClass(), 'admin', 'password');

        $this->assertInstanceOf(RuntimeException::class, $result);
        $this->assertSame('2FA required', $result->getMessage());
    }

    public function testTwoFactorPassTriggersHook(): void
    {
        $store = new InMemoryLoginAttemptStore();
        $options = $this->options();
        $options['auth']['two_factor']['enabled'] = true;
        $limiter = $this->createLimiter($store, $options, 100);

        $GLOBALS['wprtwaf_two_factor_response'] = true;

        $user = new \stdClass();
        $result = $limiter->enforceTwoFactor($user, 'admin', 'password');

        $this->assertSame($user, $result);
        $this->assertTrue($GLOBALS['wprtwaf_two_factor_action_called']);
    }

    /**
     * @return array<string, mixed>
     */
    private function options(): array
    {
        return [
            'trusted_proxies' => [],
            'auth' => [
                'login_limit' => [
                    'enabled' => true,
                    'ip_max' => 2,
                    'user_max' => 2,
                    'window' => 120,
                    'lockout' => 300,
                    'lock_message' => 'Locked',
                ],
                'two_factor' => [
                    'enabled' => false,
                    'failure_message' => '2FA required',
                ],
            ],
        ];
    }

    private function createLimiter(LoginAttemptStoreInterface $store, array $options, int $time): LoginLimiter
    {
        $resolver = new ClientIpResolver(static fn (): array => $options);

        return new LoginLimiter(
            $store,
            $resolver,
            static fn (): array => $options,
            static fn (): int => $time
        );
    }
}

class InMemoryLoginAttemptStore implements LoginAttemptStoreInterface
{
    /** @var array<string, array<int>> */
    private array $attempts = [];

    /** @var array<string, int> */
    private array $locks = [];

    public function recordAttempt(string $key, int $window, int $now): int
    {
        $events = $this->attempts[$key] ?? [];
        $threshold = $now - $window;
        $filtered = [];
        foreach ($events as $timestamp) {
            if ($timestamp > $threshold) {
                $filtered[] = $timestamp;
            }
        }

        $filtered[] = $now;
        $this->attempts[$key] = $filtered;

        return count($filtered);
    }

    public function clearAttempts(string $key): void
    {
        unset($this->attempts[$key], $this->locks[$key]);
    }

    public function isLocked(string $key, int $now): bool
    {
        return isset($this->locks[$key]) && $this->locks[$key] > $now;
    }

    public function lock(string $key, int $duration, int $now): void
    {
        $this->locks[$key] = $now + $duration;
    }
}

}
