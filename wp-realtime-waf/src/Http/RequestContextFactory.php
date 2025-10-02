<?php

namespace WPRTWAF\Http;

class RequestContextFactory
{
    public function fromGlobals(): RequestContext
    {
        $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $headers = $this->normalizeHeaders($this->extractHeaders());
        $query = $_GET ?? [];
        $bodyParams = $_POST ?? [];
        $cookies = $_COOKIE ?? [];
        $rawBody = $this->getRawBody();
        $server = $_SERVER ?? [];

        return new RequestContext($method, $uri, $headers, $query, $bodyParams, $cookies, $rawBody, $server);
    }

    /**
     * @param array<string, string> $headers
     * @return array<string, string>
     */
    private function normalizeHeaders(array $headers): array
    {
        $normalized = [];
        foreach ($headers as $name => $value) {
            $normalized[strtolower($name)] = $value;
        }

        return $normalized;
    }

    /**
     * @return array<string, string>
     */
    private function extractHeaders(): array
    {
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            if (is_array($headers)) {
                /** @var array<string, string> $headers */
                return $headers;
            }
        }

        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (str_starts_with($key, 'HTTP_')) {
                $name = str_replace('_', '-', strtolower(substr($key, 5)));
                $headers[$name] = is_array($value) ? implode(',', $value) : (string) $value;
            }
        }

        return $headers;
    }

    private function getRawBody(): string
    {
        $raw = file_get_contents('php://input');
        return is_string($raw) ? $raw : '';
    }
}
