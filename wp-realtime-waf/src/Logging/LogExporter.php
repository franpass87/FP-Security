<?php

namespace WPRTWAF\Logging;

class LogExporter
{
    /**
     * @param array<int, array<string, mixed>> $events
     */
    public function toJson(array $events): string
    {
        return json_encode($events, JSON_PRETTY_PRINT) ?: '[]';
    }

    /**
     * @param array<int, array<string, mixed>> $events
     */
    public function toCsv(array $events): string
    {
        $columns = ['timestamp', 'decision', 'severity', 'ip', 'method', 'path', 'reason', 'rule_id'];
        $handle = fopen('php://temp', 'w+');
        if ($handle === false) {
            return '';
        }

        fputcsv($handle, $columns);

        foreach ($events as $event) {
            $row = [];
            foreach ($columns as $column) {
                $row[] = is_scalar($event[$column] ?? '') ? (string) $event[$column] : json_encode($event[$column] ?? '');
            }

            fputcsv($handle, $row);
        }

        rewind($handle);
        $csv = stream_get_contents($handle);
        fclose($handle);

        return $csv === false ? '' : $csv;
    }
}
