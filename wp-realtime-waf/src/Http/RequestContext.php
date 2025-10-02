<?php

namespace WPRTWAF\Http;

class RequestContext
{
    /**
     * @param array<string, string> $headers
     * @param array<string, mixed> $query
     * @param array<string, mixed> $body
     * @param array<string, mixed> $cookies
     * @param array<string, mixed> $server
     */
    public function __construct(
        public readonly string $method,
        public readonly string $uri,
        public readonly array $headers,
        public readonly array $query,
        public readonly array $body,
        public readonly array $cookies,
        public readonly string $rawBody,
        public readonly array $server
    ) {
    }
}
