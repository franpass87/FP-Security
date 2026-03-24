# Changelog

## [1.4.0] - 2025-03-23

### Added
- Protezione PHP in uploads: .htaccess in wp-content/uploads blocca esecuzione di .php, .phtml, .phar, ecc. (Apache)
- Blocco upload pericolosi: rifiuta file con estensioni rischiose (php, phar, exe, sh, ecc.) anche in doppia estensione
- Sezione "Protezione Upload" in Impostazioni con due toggle indipendenti

## [1.3.0] - 2025-03-23

### Added
- Blocklist manuale: form per aggiungere IP alla blocklist (uno per riga)
- Audit log: registrazione login admin, salvataggio impostazioni FP Security, attivazione/disattivazione plugin
- Widget dashboard WP: ultimi 10 eventi FP Security con link al Log

### Changed
- Action `fp_security_settings_saved` lanciata dopo salvataggio impostazioni (per audit/estensibilità)

## [1.2.0] - 2025-03-23

### Added
- Blocklist IP persistente: IP bloccati a tempo indeterminato dal firewall
- Aggiunta automatica alla blocklist dopo N lockout (impostabile, 0=disabilitato)
- Notifiche email su lockout (toggle + email destinatario)
- Pagina Blocklist IP con rimozione manuale
- Esporta log in CSV
- Pulsante "Sblocca il mio IP" nella pagina Log
- Action `fp_security_login_lockout` per estensibilità

## [1.1.2] - 2025-03-23

### Added
- Whitelist IP per login: IP in whitelist non subiscono lockout (campo in Impostazioni → Protezione Login)
- Filter `fp_security_firewall_skip` per escludere richieste dal firewall (estendibilità)
- Filter `fp_security_login_whitelist` per aggiungere IP alla whitelist via codice
- Retention log: elimina voci oltre 90 giorni (filtro `fp_security_log_max_age_days`)

### Changed
- Pattern firewall più precisi: `base64_decode(`, `gzinflate(`, ecc. per ridurre falsi positivi su URL legittimi
- Aggiunti pattern assert( e create_function( al blocco query

## [1.1.1] - 2025-03-23

### Fixed
- Fail-safe: errore in init non blocca più il sito (log + notice admin invece di fatal)
- Moduli isolati: un modulo in errore non blocca gli altri
- Firewall: skip su WP-CLI, cron, REST per evitare falsi positivi
- Firewall: non blocca wp-cron.php e admin-ajax.php con user-agent vuoto
- Logger e Htaccess: try-catch per evitare crash
- Costante FP_SECURITY_DISABLED per disattivazione d'emergenza

## [1.1.0] - 2025-03-23

### Added
- Security Headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, HSTS)
- Protezione .htaccess per file sensibili (Apache)
- Integrazione: FP-Performance cede sicurezza a FP-Security quando attivo

## [1.0.0] - 2025-03-23

### Added
- Hardening WordPress: nasconde versione, disabilita file edit, XML-RPC, REST users, WLW/RSD
- Protezione login: limite tentativi, lockout temporaneo
- Firewall: blocca path e query sospette
- Log eventi di sicurezza
- Pagine admin: Dashboard, Impostazioni, Log (design system FP)
