<?php

namespace WPRTWAF\Http;

use WPRTWAF\Actions\Decision;
use WPRTWAF\RateLimit\RateLimiterInterface;

class PreFilter
{
    /**
     * @var \Closure
     */
    private readonly \Closure $optionsProvider;

    public function __construct(
        callable $optionsProvider,
        private readonly RateLimiterInterface $rateLimiter
    ) {
        $this->optionsProvider = \Closure::fromCallable($optionsProvider);
    }

    public function evaluate(NormalizedRequest $request): ?PreFilterDecision
    {
        $ip = $request->getIp();
        $options = ($this->optionsProvider)();
        $allowlist = $this->normalizeList($options['ip_allowlist'] ?? []);
        $blocklist = $this->normalizeList($options['ip_blocklist'] ?? []);
        $uaBlocklist = $this->normalizeList($options['user_agent_blocklist'] ?? []);

        if ($ip !== '' && $allowlist !== [] && $this->ipMatchesList($ip, $allowlist)) {
            return new PreFilterDecision(Decision::ALLOW, 'ip_allowlist');
        }

        if ($ip !== '' && $blocklist !== [] && $this->ipMatchesList($ip, $blocklist)) {
            return new PreFilterDecision(Decision::BLOCK, 'ip_blocklist');
        }

        $userAgent = $request->getHeader('user-agent');
        if ($userAgent !== '' && $uaBlocklist !== [] && $this->valueMatchesList($userAgent, $uaBlocklist)) {
            return new PreFilterDecision(Decision::BLOCK, 'user_agent_blocklist');
        }

        if (!$this->rateLimiter->allow($request)) {
            return new PreFilterDecision(Decision::BLOCK, 'rate_limit');
        }

        return null;
    }

    /**
     * @param array<int, string>|string $list
     * @return array<int, string>
     */
    private function normalizeList(array|string $list): array
    {
        if (is_string($list)) {
            $list = preg_split('/\r?\n/', $list) ?: [];
        }

        if (!is_array($list)) {
            return [];
        }

        return array_values(array_filter(array_map('trim', $list)));
    }

    /**
     * @param array<int, string> $list
     */
    private function ipMatchesList(string $ip, array $list): bool
    {
        foreach ($list as $entry) {
            if ($entry === '') {
                continue;
            }

            if (str_contains($entry, '/')) {
                if ($this->cidrMatch($ip, $entry)) {
                    return true;
                }
                continue;
            }

            if ($ip === $entry) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<int, string> $list
     */
    private function valueMatchesList(string $value, array $list): bool
    {
        foreach ($list as $entry) {
            if ($entry === '') {
                continue;
            }

            if ($entry[0] === '/' && strrpos($entry, '/') !== 0) {
                if (@preg_match($entry, $value)) {
                    return true;
                }
                continue;
            }

            if (function_exists('fnmatch')) {
                if (fnmatch($entry, $value)) {
                    return true;
                }
                continue;
            }

            if (stripos($value, $entry) !== false) {
                return true;
            }
        }

        return false;
    }

    private function cidrMatch(string $ip, string $cidr): bool
    {
        [$subnet, $mask] = array_pad(explode('/', $cidr, 2), 2, null);
        if ($subnet === null || $mask === null) {
            return false;
        }

        $mask = (int) $mask;

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ipLong = ip2long($ip);
            $subnetLong = ip2long($subnet);
            if ($ipLong === false || $subnetLong === false) {
                return false;
            }

            $maskLong = -1 << (32 - $mask);

            return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ipBin = inet_pton($ip);
            $subnetBin = inet_pton($subnet);
            if (!is_string($ipBin) || !is_string($subnetBin)) {
                return false;
            }

            $bytes = intdiv($mask, 8);
            $bits = $mask % 8;

            if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
                return false;
            }

            if ($bits === 0) {
                return true;
            }

            $maskByte = chr((~(255 >> $bits)) & 255);

            return (ord($ipBin[$bytes]) & ord($maskByte)) === (ord($subnetBin[$bytes]) & ord($maskByte));
        }

        return false;
    }
}
