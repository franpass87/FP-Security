<?php

declare(strict_types=1);

namespace FP\Security\Blocklist;

/**
 * Blocklist IP persistente: IP bloccati a tempo indeterminato (wp_options).
 */
final class IpBlocklist {

    private const OPTION_KEY = 'fp_security_blocklist';
    private const MAX_ENTRIES = 500;

    /**
     * @return list<string>
     */
    public function get(): array {
        $data = get_option(self::OPTION_KEY, []);
        if (!is_array($data)) {
            return [];
        }
        $ips = $data['ips'] ?? [];
        return is_array($ips) ? array_values(array_filter($ips, static fn($ip) => is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP))) : [];
    }

    public function contains(string $ip): bool {
        return in_array($ip, $this->get(), true);
    }

    public function add(string $ip): bool {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        $ips = $this->get();
        if (in_array($ip, $ips, true)) {
            return true;
        }
        $ips[] = $ip;
        $ips = array_slice(array_unique($ips), 0, self::MAX_ENTRIES);
        return update_option(self::OPTION_KEY, ['ips' => $ips, 'updated' => current_time('mysql')]);
    }

    /**
     * Aggiunge più IP (uno per riga). Ritorna numero di IP effettivamente aggiunti.
     *
     * @return int Numero di IP nuovi aggiunti (esclude duplicati e invalid)
     */
    public function add_from_text(string $text): int {
        $lines = array_filter(array_map('trim', explode("\n", $text)));
        $added = 0;
        foreach ($lines as $ip) {
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) && !$this->contains($ip) && $this->add($ip)) {
                $added++;
            }
        }
        return $added;
    }

    public function remove(string $ip): bool {
        $ips = array_values(array_filter($this->get(), static fn($i) => $i !== $ip));
        return update_option(self::OPTION_KEY, ['ips' => $ips, 'updated' => current_time('mysql')]);
    }

    public function clear_lockout(string $ip): void {
        delete_transient('fp_security_login_attempts_' . md5($ip));
        delete_transient('fp_security_lockout_' . md5($ip));
    }
}
