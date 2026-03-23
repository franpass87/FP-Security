<<<<<<< HEAD
# FP-Security
=======
# FP Security

![Version](https://img.shields.io/badge/version-1.3.0-blue)
![PHP](https://img.shields.io/badge/PHP-8.1%2B-777BB4?logo=php)
![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-21759B?logo=wordpress)

Plugin WordPress per la sicurezza: firewall, hardening, protezione login. Alternativa leggera e modulare a Wordfence.

## Funzionalità

- **Hardening WordPress**: nasconde versione WP, disabilita modifica file, XML-RPC, REST /users, rimuove WLW/RSD
- **Protezione Login**: limite tentativi, lockout temporaneo, whitelist IP, blocklist automatica
- **Firewall**: blocca path sospetti, query malevole, IP in blocklist
- **Blocklist IP**: IP bloccati permanentemente, aggiunta manuale (uno per riga), gestione
- **Notifiche**: email su lockout
- **Log**: eventi, export CSV, sblocco IP, audit admin (login, impostazioni, plugin)
- **Widget dashboard**: ultimi eventi sulla dashboard WP

## Requisiti

- PHP 8.1+
- WordPress 6.0+

## Installazione

1. Clona in `wp-content/plugins/FP-Security` (o crea junction verso cartella LAB)
2. `composer install`
3. Attiva il plugin in WordPress

## Struttura

```
FP-Security/
├── fp-security.php       # Entry point
├── src/
│   ├── Core/Plugin.php
│   ├── Hardening/HardeningManager.php
│   ├── LoginProtection/LoginGuard.php
│   ├── Firewall/RequestFilter.php
│   ├── Log/SecurityLogger.php
│   ├── Audit/AuditLog.php
│   ├── Admin/AdminMenu.php
│   └── Admin/DashboardWidget.php
└── assets/css/admin.css
```

## Hook e filtri

| Hook/Filter | Tipo | Descrizione |
|-------------|------|-------------|
| `fp_security_firewall_skip` | filter | `apply_filters('fp_security_firewall_skip', $skip, $uri, $query)` — ritorna true per saltare il firewall |
| `fp_security_login_whitelist` | filter | `apply_filters('fp_security_login_whitelist', $ips_string)` — aggiungi IP alla whitelist (uno per riga) |
| `fp_security_log_max_age_days` | filter | `apply_filters('fp_security_log_max_age_days', 90)` — retention log in giorni (0 = nessun limite età) |
| `fp_security_settings_saved` | action | `do_action('fp_security_settings_saved', $settings)` — dopo salvataggio impostazioni |

## Autore

**Francesco Passeri**
- Sito: [francescopasseri.com](https://francescopasseri.com)
- Email: [info@francescopasseri.com](mailto:info@francescopasseri.com)
- GitHub: [github.com/franpass87](https://github.com/franpass87)
>>>>>>> d725801 (feat: blocklist manuale, audit log, widget dashboard (v 1.3.0))
