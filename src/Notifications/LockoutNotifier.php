<?php

declare(strict_types=1);

namespace FP\Security\Notifications;

/**
 * Notifiche email su eventi critici (lockout, ecc.).
 */
final class LockoutNotifier {

    public function register_hooks(): void {
        add_action('fp_security_login_lockout', [$this, 'on_lockout'], 10, 2);
    }

    /**
     * @param array{ip?: string, attempts?: int} $ctx
     */
    public function on_lockout(string $event, array $ctx): void {
        $settings = $this->get_settings();
        if (empty($settings['email_on_lockout'])) {
            return;
        }

        $to = $settings['notification_email'] ?? get_option('admin_email');
        $to = is_email($to) ? $to : get_option('admin_email');
        if (!$to) {
            return;
        }

        $ip = $ctx['ip'] ?? '?';
        $attempts = $ctx['attempts'] ?? 0;
        $subject = sprintf(
            '[%s] %s',
            wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES),
            __('FP Security: Lockout login rilevato', 'fp-security')
        );
        $body = sprintf(
            __("Un indirizzo IP è stato bloccato per troppi tentativi di login falliti.\n\nIP: %s\nTentativi: %d\nSito: %s\n", 'fp-security'),
            $ip,
            $attempts,
            home_url()
        );

        $subject = str_replace(["\r", "\n"], '', $subject);

        try {
            wp_mail($to, $subject, $body, ['Content-Type: text/plain; charset=UTF-8']);
        } catch (Throwable $e) {
            if (function_exists('error_log')) {
                error_log('[FP-Security] Email lockout failed: ' . $e->getMessage());
            }
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function get_settings(): array {
        $saved = get_option('fp_security_settings', []);
        $saved = is_array($saved) ? $saved : [];
        $n = $saved['notifications'] ?? [];
        $n = is_array($n) ? $n : [];
        return wp_parse_args($n, [
            'email_on_lockout'   => false,
            'notification_email' => get_option('admin_email'),
        ]);
    }
}
