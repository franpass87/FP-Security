<?php

namespace WPRTWAF\Http;

class ClientIpResolver
{
    /**
     * @var \Closure
     */
    private readonly \Closure $optionsProvider;

    /**
     * @param callable(): array<string, mixed> $optionsProvider
     */
    public function __construct(callable $optionsProvider)
    {
        $this->optionsProvider = \Closure::fromCallable($optionsProvider);
    }

    public function resolve(array $server, array $headers): string
    {
        $remoteAddr = (string) ($server['REMOTE_ADDR'] ?? '');
        $trustedProxies = $this->getTrustedProxies();

        if ($remoteAddr === '') {
            return '';
        }

        if ($trustedProxies === []) {
            return $remoteAddr;
        }

        if (!$this->ipMatchesList($remoteAddr, $trustedProxies)) {
            return $remoteAddr;
        }

        $forwardedFor = $headers['x-forwarded-for'] ?? ($server['HTTP_X_FORWARDED_FOR'] ?? '');
        if (!is_string($forwardedFor) || $forwardedFor === '') {
            return $remoteAddr;
        }

        $parts = array_filter(array_map('trim', explode(',', $forwardedFor)), static fn ($value) => $value !== '');
        if ($parts === []) {
            return $remoteAddr;
        }

        return (string) $parts[0];
    }

    /**
     * @return array<int, string>
     */
    private function getTrustedProxies(): array
    {
        $options = ($this->optionsProvider)();
        $proxies = $options['trusted_proxies'] ?? [];
        if (!is_array($proxies)) {
            return [];
        }

        return array_values(array_filter(array_map('trim', $proxies))); 
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

            if ($this->ipMatches($ip, $entry)) {
                return true;
            }
        }

        return false;
    }

    private function ipMatches(string $ip, string $rule): bool
    {
        if (str_contains($rule, '/')) {
            return $this->cidrMatch($ip, $rule);
        }

        return $ip === $rule;
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
