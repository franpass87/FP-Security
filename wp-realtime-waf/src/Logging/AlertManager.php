<?php

namespace WPRTWAF\Logging;

class AlertManager
{
    /** @var \Closure */
    private readonly \Closure $optionsProvider;

    /** @var callable */
    private $mailer;

    /** @var callable */
    private $requester;

    /** @var array<string, int> */
    private array $state = ['email' => 0, 'webhook' => 0];

    private bool $stateLoaded = false;

    public function __construct(callable $optionsProvider, ?callable $mailer = null, ?callable $requester = null)
    {
        $this->optionsProvider = \Closure::fromCallable($optionsProvider);
        $this->mailer = $mailer ?? static function (string $to, string $subject, string $message): bool {
            if (function_exists('wp_mail')) {
                return (bool) wp_mail($to, $subject, $message);
            }

            return false;
        };
        $this->requester = $requester ?? static function (string $url, array $payload): void {
            if (!function_exists('wp_remote_post')) {
                return;
            }

            $body = function_exists('wp_json_encode') ? wp_json_encode($payload) : json_encode($payload);

            wp_remote_post($url, [
                'timeout' => 5,
                'headers' => ['Content-Type' => 'application/json'],
                'body' => $body,
            ]);
        };
    }

    public function handle(Event $event): void
    {
        $options = ($this->optionsProvider)();
        $logging = is_array($options['logging'] ?? null) ? $options['logging'] : [];
        $alerts = is_array($logging['alerts'] ?? null) ? $logging['alerts'] : [];

        $minSeverity = $this->normalizeSeverity($alerts['min_severity'] ?? 'high');
        $onlyBlocking = !empty($alerts['only_blocking']);

        if ($this->severityRank($event->severity) < $this->severityRank($minSeverity)) {
            return;
        }

        if ($onlyBlocking && !$event->isBlocking()) {
            return;
        }

        $throttle = (int) ($alerts['throttle'] ?? 300);

        if (!empty($alerts['email']['enabled'])) {
            $recipient = $alerts['email']['recipient'] ?? $this->defaultAdminEmail();
            if (is_string($recipient) && $recipient !== '' && !$this->isThrottled('email', $throttle)) {
                $this->sendEmail($recipient, $event, $alerts);
                $this->markSent('email');
            }
        }

        if (!empty($alerts['webhook']['enabled'])) {
            $url = $alerts['webhook']['url'] ?? '';
            if (is_string($url) && $url !== '' && !$this->isThrottled('webhook', $throttle)) {
                $secret = is_string($alerts['webhook']['secret'] ?? null) ? $alerts['webhook']['secret'] : '';
                $this->sendWebhook($url, $event, $secret);
                $this->markSent('webhook');
            }
        }
    }

    private function sendEmail(string $recipient, Event $event, array $alerts): void
    {
        $subject = sprintf('[WP Realtime WAF] %s decision', ucfirst($event->decision));
        $message = sprintf(
            "Severity: %s\nDecision: %s\nReason: %s\nPath: %s\nIP: %s\nRule: %s",
            ucfirst($event->severity),
            $event->decision,
            $event->reason,
            $event->path,
            $event->ip,
            $event->ruleId ?? 'builtin'
        );

        ($this->mailer)($recipient, $subject, $message);
    }

    private function sendWebhook(string $url, Event $event, string $secret): void
    {
        $payload = [
            'id' => $event->id,
            'timestamp' => $event->timestamp,
            'decision' => $event->decision,
            'severity' => $event->severity,
            'ip' => $event->ip,
            'path' => $event->path,
            'method' => $event->method,
            'rule_id' => $event->ruleId,
            'reason' => $event->reason,
        ];

        if ($secret !== '') {
            $body = json_encode($payload) ?: '';
            $payload['signature'] = hash_hmac('sha256', $body, $secret);
        }

        ($this->requester)($url, $payload);
    }

    private function severityRank(string $severity): int
    {
        return match ($this->normalizeSeverity($severity)) {
            'critical' => 4,
            'high' => 3,
            'medium' => 2,
            'low' => 1,
            default => 0,
        };
    }

    private function normalizeSeverity(mixed $severity): string
    {
        $value = strtolower(is_string($severity) ? $severity : 'medium');

        return match ($value) {
            'critical', 'high', 'medium', 'low' => $value,
            default => 'high',
        };
    }

    private function isThrottled(string $channel, int $throttle): bool
    {
        $state = $this->loadState();
        $last = $state[$channel] ?? 0;

        if ($throttle <= 0) {
            return false;
        }

        return (time() - (int) $last) < $throttle;
    }

    private function markSent(string $channel): void
    {
        $state = $this->loadState();
        $state[$channel] = time();
        $this->state = $state;
        $this->persistState();
    }

    /**
     * @return array<string, int>
     */
    private function loadState(): array
    {
        if ($this->stateLoaded) {
            return $this->state;
        }

        if (function_exists('get_option')) {
            $value = get_option('wp_realtime_waf_alert_state', []);
            if (is_array($value)) {
                $this->state = array_map('intval', $value);
            }
        }

        $this->stateLoaded = true;

        return $this->state;
    }

    private function persistState(): void
    {
        if (function_exists('update_option')) {
            update_option('wp_realtime_waf_alert_state', $this->state);
        }
    }

    private function defaultAdminEmail(): string
    {
        if (function_exists('get_option')) {
            $email = get_option('admin_email');
            if (is_string($email)) {
                return $email;
            }
        }

        return '';
    }
}
