<?php

namespace WPRTWAF\Logging;

class OptionsEventStore implements EventStoreInterface
{
    private array $cache = [];

    private bool $loaded = false;

    public function __construct(
        private readonly string $optionKey = 'wp_realtime_waf_events',
        private int $maxEvents = 500
    ) {
        $this->maxEvents = max(1, $this->maxEvents);
    }

    public function setMaxEvents(int $maxEvents): void
    {
        $this->maxEvents = max(1, $maxEvents);
        $events = $this->load();
        if (count($events) > $this->maxEvents) {
            $events = array_slice($events, -1 * $this->maxEvents);
            $this->persist($events);
        }
    }

    public function append(Event $event): void
    {
        $events = $this->load();
        $events[] = $event->toArray();

        if (count($events) > $this->maxEvents) {
            $events = array_slice($events, -1 * $this->maxEvents);
        }

        $this->persist($events);
    }

    public function getEvents(int $limit, int $offset = 0): array
    {
        $events = $this->load();
        $limit = max(1, $limit);
        $offset = max(0, $offset);

        return array_reverse(array_slice($events, max(0, count($events) - ($offset + $limit)), $limit));
    }

    public function all(): array
    {
        return $this->load();
    }

    public function count(): int
    {
        return count($this->load());
    }

    public function getDecisionCounts(): array
    {
        $counts = [];
        foreach ($this->load() as $event) {
            $decision = is_string($event['decision'] ?? null) ? strtolower($event['decision']) : 'unknown';
            $counts[$decision] = ($counts[$decision] ?? 0) + 1;
        }

        ksort($counts);

        return $counts;
    }

    public function getTopAttackers(int $limit = 5): array
    {
        $limit = max(1, $limit);
        $totals = [];
        foreach ($this->load() as $event) {
            $ip = is_string($event['ip'] ?? null) ? $event['ip'] : 'unknown';
            $totals[$ip] = ($totals[$ip] ?? 0) + 1;
        }

        arsort($totals);

        $result = [];
        foreach (array_slice($totals, 0, $limit, true) as $ip => $count) {
            $result[] = ['ip' => $ip, 'count' => $count];
        }

        return $result;
    }

    public function replace(array $events): void
    {
        $sanitized = [];
        foreach ($events as $event) {
            if (is_array($event)) {
                $sanitized[] = $event;
            }
        }

        if (count($sanitized) > $this->maxEvents) {
            $sanitized = array_slice($sanitized, -1 * $this->maxEvents);
        }

        $this->persist($sanitized);
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function load(): array
    {
        if ($this->loaded) {
            return $this->cache;
        }

        if (!function_exists('get_option')) {
            $this->cache = $this->cache ?: [];
            $this->loaded = true;

            return $this->cache;
        }

        $value = get_option($this->optionKey, []);
        $this->cache = is_array($value) ? array_values($value) : [];
        $this->loaded = true;

        return $this->cache;
    }

    private function persist(array $events): void
    {
        $this->cache = array_values($events);
        $this->loaded = true;

        if (function_exists('update_option')) {
            update_option($this->optionKey, $this->cache);
        }
    }
}
