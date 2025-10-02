<?php

namespace WPRTWAF\Http;

class NormalizedRequest
{
    /**
     * @param array<string, string> $headers
     * @param array<string, string> $query
     * @param array<string, string> $body
     * @param array<string, string> $cookies
     */
    public function __construct(
        private readonly string $method,
        private readonly string $uri,
        private readonly string $ip,
        private readonly array $headers,
        private readonly array $query,
        private readonly array $body,
        private readonly array $cookies,
        private readonly string $rawBody
    ) {
    }

    public function getMethod(): string
    {
        return $this->method;
    }

    public function getPath(): string
    {
        $path = parse_url($this->uri, PHP_URL_PATH);

        return is_string($path) ? $path : '/';
    }

    public function getUri(): string
    {
        return $this->uri;
    }

    public function getIp(): string
    {
        return $this->ip;
    }

    public function getUserAgent(): string
    {
        $ua = $this->getHeader('user-agent');

        return $ua !== '' ? $ua : ($this->headers['user-agent'] ?? '');
    }

    public function getHeader(string $name): string
    {
        $key = strtolower($name);

        return $this->headers[$key] ?? '';
    }

    /**
     * @return array<string, string>
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * @return array<string, string>
     */
    public function getQuery(): array
    {
        return $this->query;
    }

    /**
     * @return array<string, string>
     */
    public function getBody(): array
    {
        return $this->body;
    }

    /**
     * @return array<string, string>
     */
    public function getCookies(): array
    {
        return $this->cookies;
    }

    public function getRawBody(): string
    {
        return $this->rawBody;
    }

    public function getAggregatePayload(): string
    {
        return implode('\n', [
            $this->method,
            $this->uri,
            implode('&', $this->query),
            implode('&', $this->body),
            implode('&', $this->headers),
            implode('&', $this->cookies),
            $this->rawBody,
        ]);
    }

    public function getTargetValue(string $target): string
    {
        return match ($target) {
            'method' => $this->method,
            'uri', 'path' => $this->uri,
            'query' => implode('\n', $this->query),
            'body' => $this->rawBody !== '' ? $this->rawBody : implode('\n', $this->body),
            'headers' => implode('\n', $this->headers),
            'cookies' => implode('\n', $this->cookies),
            'all' => $this->getAggregatePayload(),
            default => '',
        };
    }
}
