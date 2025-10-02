<?php

namespace WPRTWAF\Auth;

use Closure;
use RuntimeException;
use WPRTWAF\Http\ClientIpResolver;

class LoginLimiter
{
    /** @var Closure */
    private readonly Closure $optionsProvider;

    /** @var Closure */
    private readonly Closure $timeProvider;

    public function __construct(
        private readonly LoginAttemptStoreInterface $store,
        private readonly ClientIpResolver $ipResolver,
        callable $optionsProvider,
        ?callable $timeProvider = null
    ) {
        $this->optionsProvider = Closure::fromCallable($optionsProvider);
        $this->timeProvider = $timeProvider !== null ? Closure::fromCallable($timeProvider) : static fn (): int => time();
    }

    public function register(): void
    {
        if (!function_exists('add_filter')) {
            return;
        }

        add_filter('authenticate', [$this, 'enforceLock'], 5, 3);
        add_filter('authenticate', [$this, 'enforceTwoFactor'], 50, 3);
        add_action('wp_login_failed', [$this, 'recordFailure']);
        add_action('wp_login', [$this, 'recordSuccess'], 10, 2);
    }

    /**
     * @param mixed $user
     * @return mixed
     */
    public function enforceLock($user, string $username, string $password)
    {
        $config = $this->getConfig();
        if (!$config['enabled']) {
            return $user;
        }

        $ip = $this->resolveIp();
        $now = ($this->timeProvider)();

        $keys = $this->keys($ip, $username);
        foreach ($keys as $key) {
            if ($this->store->isLocked($key, $now)) {
                return $this->error('wprtwaf_login_locked', $config['lock_message']);
            }
        }

        return $user;
    }

    /**
     * @param mixed $user
     * @return mixed
     */
    public function enforceTwoFactor($user, string $username, string $password)
    {
        $config = $this->getConfig();
        $twoFactor = $config['two_factor'];
        if (!$twoFactor['enabled'] || !is_object($user)) {
            return $user;
        }

        $ip = $this->resolveIp();
        $result = true;

        if (function_exists('apply_filters')) {
            $result = apply_filters('wp_realtime_waf_two_factor_authenticate', true, $user, $ip, $twoFactor);
        }

        if ($result instanceof \WP_Error) {
            return $result;
        }

        if ($result === false) {
            return $this->error('wprtwaf_two_factor_required', $twoFactor['failure_message']);
        }

        if (function_exists('do_action')) {
            do_action('wp_realtime_waf_two_factor_challenge', $user, $ip, $twoFactor);
        }

        return $user;
    }

    public function recordFailure(string $username): void
    {
        $config = $this->getConfig();
        if (!$config['enabled']) {
            return;
        }

        $now = ($this->timeProvider)();
        $ip = $this->resolveIp();
        $window = max(1, $config['window']);
        $lockout = max(1, $config['lockout']);

        $keys = $this->keys($ip, $username);
        foreach ($keys as $type => $key) {
            $count = $this->store->recordAttempt($key, $window, $now);
            $threshold = $type === 'ip' ? $config['ip_max'] : $config['user_max'];
            if ($threshold > 0 && $count > $threshold) {
                $this->store->lock($key, $lockout, $now);
            }
        }
    }

    public function recordSuccess(string $userLogin, mixed $user): void
    {
        $config = $this->getConfig();
        if (!$config['enabled']) {
            return;
        }

        $ip = $this->resolveIp();
        foreach ($this->keys($ip, $userLogin) as $key) {
            $this->store->clearAttempts($key);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function getConfig(): array
    {
        $options = ($this->optionsProvider)();
        $auth = $options['auth'] ?? [];
        $login = $auth['login_limit'] ?? [];
        $twoFactor = $auth['two_factor'] ?? [];

        return [
            'enabled' => (bool) ($login['enabled'] ?? false),
            'ip_max' => $this->positiveInt($login['ip_max'] ?? 0),
            'user_max' => $this->positiveInt($login['user_max'] ?? 0),
            'window' => $this->positiveInt($login['window'] ?? 900),
            'lockout' => $this->positiveInt($login['lockout'] ?? 900),
            'lock_message' => $this->translate((string) ($login['lock_message'] ?? 'Too many login attempts. Please try again later.')),
            'two_factor' => [
                'enabled' => (bool) ($twoFactor['enabled'] ?? false),
                'failure_message' => $this->translate((string) ($twoFactor['failure_message'] ?? 'Two-factor authentication required.')),
            ],
        ];
    }

    private function resolveIp(): string
    {
        $server = $_SERVER ?? [];
        $headers = [];
        foreach ($server as $key => $value) {
            if (str_starts_with((string) $key, 'HTTP_')) {
                $name = strtolower(str_replace('_', '-', substr((string) $key, 5)));
                $headers[$name] = is_array($value) ? implode(',', $value) : (string) $value;
            }
        }

        return $this->ipResolver->resolve(is_array($server) ? $server : [], $headers);
    }

    /**
     * @return array<string, string>
     */
    private function keys(string $ip, string $username): array
    {
        $keys = [];
        if ($ip !== '') {
            $keys['ip'] = 'wprtwaf:login:ip:' . hash('sha256', $ip);
        }

        $username = trim($username);
        if ($username !== '') {
            $keys['user'] = 'wprtwaf:login:user:' . hash('sha256', strtolower($username));
        }

        return $keys;
    }

    private function error(string $code, string $message)
    {
        if (class_exists('\\WP_Error')) {
            return new \WP_Error($code, $message, ['status' => 403]);
        }

        return new RuntimeException($message);
    }

    private function positiveInt(mixed $value): int
    {
        $value = filter_var($value, FILTER_VALIDATE_INT);

        return $value !== false && $value > 0 ? (int) $value : 0;
    }

    private function translate(string $text): string
    {
        if (function_exists('__')) {
            return __($text, 'wp-realtime-waf');
        }

        return $text;
    }
}
