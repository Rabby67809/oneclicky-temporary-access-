# OneClicky – Temporary Access & Guard Control

A WordPress plugin for creating and managing **time-limited invitation login links** without giving recipients the site owner's personal password.

**Version:** 1.16.0  
**WordPress:** 6.2+  
**PHP:** 7.4+  
**Author:** Rejoyan9009  
**License:** GPL-2.0-or-later

> **Security warning:** An invitation with the native WordPress **Administrator** role grants real Administrator capabilities. An Administrator can potentially execute PHP, install plugins, create other administrators, or bypass plugin-level safeguards. Issue Administrator invitations only to people you fully trust. Hiding plugin controls or denying some capabilities is not an isolation boundary.

## Features

- Site-owned, time-limited, one-time or limited-use invitation links.
- Native WordPress roles (including Administrator only when explicitly chosen and confirmed).
- Optional email one-time passwords (OTP), using the site's configured WordPress mail transport.
- Immediate invitation revocation, emergency lock, and expiration management.
- Per-invitation optional capability-deny settings; no extra restrictions by default.
- Local invitation/activity records and basic security notifications.
- Secure token handling; unused encrypted invitation secrets can be recovered only while eligible.
- No plugin-operated external remote control service, central admin dashboard, or telemetry platform.

See [`readme.txt`](readme.txt) for the complete WordPress.org plugin description, installation instructions, FAQ, privacy information, migration guidance, and changelog.

## Installation

1. Back up your WordPress site and database. Prefer testing in a staging environment first.
2. Get the installable plugin ZIP from a release, or build it with the script below.
3. In WordPress, open **Plugins → Add New → Upload Plugin** and select `oneclicky-temporary-access.zip`.
4. Activate **OneClicky – Temporary Access & Guard Control**.
5. Open **OneClicky → All Links** to manage invitations.

**Do not install this GitHub source repository ZIP directly** if it contains GitHub workflow and development files; use the plugin-only ZIP made by `scripts/build-plugin-zip.sh`.

## Build an installable ZIP

Requires `bash` and `zip` on Linux, macOS, or compatible environments:

```bash
bash scripts/build-plugin-zip.sh
```

The output is `dist/oneclicky-temporary-access.zip`, containing only the WordPress plugin files under a single `oneclicky-temporary-access/` directory.

## Source layout

| Path | Purpose |
| --- | --- |
| `oneclicky-temporary-access.php` | WordPress plugin header and bootstrap |
| `includes/` | PHP functionality and access management |
| `assets/` | Dashboard and frontend CSS/JavaScript |
| `languages/` | Translation template |
| `readme.txt` | Official-format plugin documentation and changelog |
| `uninstall.php` | Plugin uninstall cleanup logic |
| `.github/workflows/` | CI checks for source contributions |
| `scripts/` | Utility to build a plugin-only installable ZIP |

## Rebranding and migration notes

This plugin was previously called **AccessMint – Temporary Access**. The public plugin name and slug changed in v1.16.0; internal `AMTA_` PHP symbols and `amta_` database keys remain for compatibility.

WordPress treats the **new slug as a separate plugin**, not an automatic in-place upgrade. **Do not activate the old and new plugins at the same time**, as they share internal classes and tables. Deleting the old plugin through the WordPress Plugins screen can trigger uninstall cleanup and delete plugin-managed data. Follow the [migration notes in `readme.txt`](readme.txt) on a staging site and back up first. Old temporary invitations must not be assumed to keep working after migration.

## Development and testing

This repository includes lightweight continuous integration that lints PHP files on multiple PHP versions and checks that a plugin ZIP can be built. This does **not** replace runtime testing, the official WordPress Plugin Check, penetration testing, or an independent infrastructure security assessment where applicable.

Run syntax checks locally:

```bash
find . -name '*.php' -type f -exec php -l {} \;
```

Please test account creation, invitation redemption, expiry, revocation, mail OTP, and deactivation/uninstall on a disposable WordPress staging site before deploying production changes.

## WordPress.org status

The requested WordPress.org slug is `oneclicky-temporary-access`. Repository publishing does not guarantee WordPress.org listing, final name/slug reservation, or security review approval. The WordPress Plugins Team must independently confirm any remaining review concerns.

## Security and contributions

Read [SECURITY.md](SECURITY.md) for responsible vulnerability disclosure instructions and [CONTRIBUTING.md](CONTRIBUTING.md) before contributing. Never commit real invitation URLs, authentication cookies, API keys, passwords, SMTP credentials, user data or database exports.

## License

GPL version 2 or any later version at your option. See [LICENSE](LICENSE) (full GPLv2 text) and the original [LICENSE.txt](LICENSE.txt) notice.
