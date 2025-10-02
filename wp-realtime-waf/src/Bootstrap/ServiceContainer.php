<?php

namespace WPRTWAF\Bootstrap;

use InvalidArgumentException;

class ServiceContainer
{
    /** @var array<string, array{factory: callable, shared: bool}> */
    private array $definitions = [];

    /** @var array<string, mixed> */
    private array $instances = [];

    public function share(string $id, callable $factory): void
    {
        $this->definitions[$id] = [
            'factory' => $factory,
            'shared' => true,
        ];
    }

    public function factory(string $id, callable $factory): void
    {
        $this->definitions[$id] = [
            'factory' => $factory,
            'shared' => false,
        ];
    }

    public function instance(string $id, mixed $service): void
    {
        $this->instances[$id] = $service;
    }

    public function has(string $id): bool
    {
        return array_key_exists($id, $this->definitions) || array_key_exists($id, $this->instances);
    }

    public function get(string $id): mixed
    {
        if (array_key_exists($id, $this->instances)) {
            return $this->instances[$id];
        }

        if (!array_key_exists($id, $this->definitions)) {
            throw new InvalidArgumentException(sprintf('Service "%s" is not defined.', $id));
        }

        $definition = $this->definitions[$id];
        $factory = $definition['factory'];
        $service = $factory($this);

        if ($definition['shared']) {
            $this->instances[$id] = $service;
        }

        return $service;
    }
}
