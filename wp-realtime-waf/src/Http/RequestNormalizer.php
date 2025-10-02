<?php

namespace WPRTWAF\Http;

class RequestNormalizer
{
    public function __construct(private readonly ClientIpResolver $ipResolver)
    {
    }

    public function normalize(RequestContext $context): NormalizedRequest
    {
        $headers = $this->lowercaseKeys($context->headers);
        $query = $this->flatten($context->query);
        $body = $this->flatten($context->body);
        $cookies = $this->flatten($context->cookies);
        $rawBody = $context->rawBody;
        $ip = $this->ipResolver->resolve($context->server, $headers);

        return new NormalizedRequest(
            $context->method,
            $context->uri,
            $ip,
            $headers,
            $query,
            $body,
            $cookies,
            $rawBody
        );
    }

    /**
     * @param array<string, mixed> $data
     * @return array<string, string>
     */
    private function flatten(array $data, string $prefix = ''): array
    {
        $result = [];
        foreach ($data as $key => $value) {
            $composedKey = $prefix === '' ? (string) $key : $prefix . '.' . (string) $key;

            if (is_array($value)) {
                $result += $this->flatten($value, $composedKey);
                continue;
            }

            if (is_bool($value)) {
                $value = $value ? '1' : '0';
            }

            $result[$composedKey] = (string) $value;
        }

        return $result;
    }

    /**
     * @param array<string, string> $headers
     * @return array<string, string>
     */
    private function lowercaseKeys(array $headers): array
    {
        $normalized = [];
        foreach ($headers as $key => $value) {
            $normalized[strtolower((string) $key)] = is_array($value) ? implode(',', $value) : (string) $value;
        }

        return $normalized;
    }
}
