=== OneClicky – Temporary Access & Guard Control ===
Contributors: rejoyan9009
Tags: temporary access, secure login, passwordless, administrator, access management
Requires at least: 6.2
Requires PHP: 7.4
Tested up to: 7.1
Stable tag: 1.16.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Create time-limited WordPress login invitations with optional email verification, immediate revocation, access safeguards, and activity logging.

== Description ==

OneClicky – Temporary Access & Guard Control allows a site owner to create separate temporary WordPress user accounts with one-time or limited-use links. Each link can be revoked or renewed, and a live status indicates whether its holder has reached the dashboard.

The plugin retains **native WordPress roles**. Selecting Administrator assigns the actual WordPress Administrator role. No imitation workspace is used. Site owners may optionally deny selected capabilities separately for each invitation in All Links > Custom Feature Locks; by default nothing additional is denied. The temporary Administrator sees the ordinary WordPress Dashboard, Plugins, Appearance, Users and Settings according to core role permissions.

OneClicky hides its management menu and plugin row from temporary accounts and rejects ordinary WordPress admin/API actions targeting OneClicky itself. **This is not a secure isolation boundary. Full Administrators can install/execute PHP, change server-side settings, create other persistent administrators, or otherwise bypass plugin-level protections.** Only give Administrator invitations to highly trusted people. For stronger isolation, use Editor or a purpose-built restricted role instead.

Version 1.15.0 stores unredeemed invitation tokens encrypted at rest, enabling site owners to copy a valid unused link again after reloading. Encryption depends on stable WordPress auth salts and PHP Sodium or OpenSSL; older invitations cannot be recovered retroactively. Tokens are cleared when used up, revoked, or expired. OTP mail failures no longer consume the successful-send quota; short cooldowns protect against abuse.

Version 1.13.0 adds an owner-only Security Center: irreversible emergency revocation of all temporary invitations, a WordPress email transport test, optional recipient email OTP, throttled security alerts and expanded (minimal-metadata) activity events. Legacy invitations keep their old login flow unless the site owner selected OTP for a new invitation. Logs are retained for 90 days; avoid collecting private content. OTP requires functioning outgoing WordPress email.

Version 1.14.0 adds a responsive Expiry Manager on every active invitation card. View the current remaining time, choose quick presets, select a custom minutes/hours/days duration, add time to the existing expiry, or choose a specific date/time in the WordPress site timezone. Changes are previewed before saving, then validated server-side (5 minutes to 365 days from now). Original access roles, existing links and security behavior are preserved. For email delivery, use a properly configured SMTP transport; wp_mail acceptance does not guarantee delivery.

== Architecture and local administration ==

Invitation creation and management take place only within the local WordPress installation. There is no remote control service, remote management API, or shared external infrastructure provided by this plugin. A locally-authorized WordPress administrator creates an invitation; the recipient follows the site-hosted link and, after confirmation and token checks (and optional email OTP), receives a native WordPress login session for the selected role. Administrator invitations carry actual Administrator privileges, and must only be issued to trusted recipients. The site owner's existing WordPress email transport is used for optional notification email; third-party SMTP providers configured by the site owner may process messages. Access logs are stored locally.

== Features ==

* Native WordPress roles, including full Administrator when explicitly confirmed.
* Dedicated invitation accounts; recipient emails may repeat.
* 256-bit random invitation secrets verified with hashes; active unused secrets are also stored using authenticated encryption so the owner can recopy them.
* One-time or multi-use invitation links; configurable expiry.
* Bulk invitations, status tracking and activity logging.
* Revoke/restore (two-minute window), delete and advanced expiry management with before/after preview.
* Branded expired/revoked/deleted pages with an optional runner mini-game.
* Separate management interface accessible only by non-temporary administrators.
* Self-protection for standard plugin-management actions, without claiming to be tamper-proof.
* Per-invitation checkboxes for optional capability-deny rules; multiple core groups and extra plugin capabilities can be selected.
* No optional locks are set by default; changing a rule affects only the linked temporary account.

== Installation ==

1. Back up the site's database and files. Test with a staging site before using on production.
2. For a fresh installation: Plugins > Add New > Upload Plugin; select the OneClicky ZIP, then activate it.
3. Open OneClicky > All Links to review or create invitations.
4. For full Administrator invitations, read the role warning and invite only highly trusted recipients.

= Migrating from AccessMint 1.15.5 =

This release is a rebrand with a NEW plugin directory/slug. WordPress considers it a separate plugin, not an in-place update. **Do not activate both plugins together:** both share internal AMTA classes and plugin-owned tables. Back up first, then on a staging site deactivate the former plugin, replace its code via your hosting file manager or SFTP (do not delete it from the Plugins screen, because uninstall removes plugin-owned data), and activate OneClicky. Deactivation of the old plugin revokes all temporary invitations for safety; issue new invitations after the migration. The existing internal `amta_` table names are intentionally retained for compatibility. Do not rely on old invitation links continuing to work.

== Frequently Asked Questions ==

= Can a temporary Administrator use ordinary WordPress functions? =

Yes. They receive the actual Administrator role, including other plugins, users and site settings. This is potentially dangerous; grant it only to trusted people.

= Can I lock specific features without taking away the original Administrator Dashboard? =

Yes. In OneClicky > All Links, expand Custom Feature Locks for the invitation, tick capabilities to block and save. All unchecked capabilities remain controlled by the native WordPress role. You can reverse locks any time. Third-party plugins may have privileged actions that do not follow these capabilities.

= Can OneClicky make itself impossible to remove for a full Administrator? =

No. It blocks standard WordPress actions aimed at itself, but an unrestricted Administrator can bypass plugin-level defenses using code execution, other plugins or filesystem/database access. You must not rely on this protection against hostile Administrators.

= What happens to previously restricted Administrator invitations? =

Existing currently valid invitations originally created for Administrator are migrated back to the real Administrator role during the 1.11.0 update. Expired or revoked invitations are not elevated. This may materially increase the privileges of existing recipients; revoke any you do not trust before upgrading.

== Privacy and security ==

OneClicky stores invitation recipient names and email addresses in the site's WordPress database, creates temporary WordPress user accounts, and records a minimal local activity trail (event type, timestamp, invitation reference and limited action metadata). It does not send analytics or telemetry to OneClicky or another service. The administrator may choose to send invitations, login OTP codes and security notifications by email using the site's existing WordPress mail transport or SMTP provider.

Local events are pruned after 90 days by scheduled cleanup. Deleted-invitation status hashes are retained for up to 90 days. These records are not publicly accessible through the plugin UI. Site owners are responsible for notifying recipients of their site's monitoring, access and retention policies, especially when applicable data protection laws require it. Email delivery and confidentiality depend on the selected mail provider.

The plugin is intended for trusted site owners. Native Administrator invitations are powerful and must be used only with trusted recipients. Capability deny rules and hiding OneClicky's admin/plugin controls do NOT sandbox a full Administrator. A malicious Administrator may bypass plugin-level locks through PHP execution, other plugins, new users or server-level changes. For untrusted recipients, choose a less privileged WordPress role.

== Changelog ==

= 1.16.0 =
* Rename the public plugin identity to OneClicky – Temporary Access & Guard Control, with a distinct oneclicky-temporary-access slug and matching translation text domain.
* Refresh dashboard branding, user-facing messages, readme, and language catalog metadata.
* Retain AMTA internal classes, tables, metadata and invitation mechanics to minimize migration surprises. Activation under a new slug is not an automatic upgrade.
* Document local-only invitation administration, genuine WordPress Administrator risk, and safe rebrand migration on staging.


= 1.15.5 =
* Bind each count/listing SQL placeholder to its own explicitly supplied prepare() argument; resolves the two Plugin Check replacements-count warnings.
* Preserve search filtering, sortable page ordering, current roles, plugin author, and existing invitation records.

= 1.15.4 =
* Prepare listing and count SQL with fixed queries, allowlisted filters and bound identifiers/values.
* Sanitize invitation ID/token on input, and verify the POST redemption nonce before reading its token.
* Explain narrowly scoped direct custom-table queries that must remain uncached for immediate revocation, plus uninstall-only schema cleanup.
* Retain existing plugin name, slug, author, access rules, and invitation compatibility.


= 1.15.3 =
* Validate invitation confirmation nonce before token redemption and normalize status AJAX inputs.
* Prepare paginated list query SQL in one bound statement with identifier placeholders.
* Document and scope nonce-exempt read-only navigation and security-critical uncached database operations.
* Retain original invitation, Administrator and security behavior.


= 1.15.2 =
* Address Plugin Check ERROR findings: prepare dynamic database table identifiers with the WordPress 6.2+ %i placeholder, improve admin input sanitization, and add translator comments.
* Register and enqueue standalone login portal CSS/JS with WordPress APIs rather than raw tags.
* Prefix variables in uninstall and safely quote dynamic table identifiers in DROP/SELECT statements.
* Preserve temporary access functionality, encrypted unredeemed links, OTP, expiry management, and role settings.
* Recheck with the official Plugin Check on a staging site before WordPress.org submission.

= 1.15.1 =
* Align WordPress.org contributor metadata and stable release version.
* Clarify encrypted-at-rest link recovery, privacy disclosures and Administrator access limitations.
* No changes to invitation, role, OTP or session behavior.


= 1.15.0 =
* Recover active, unredeemed invitation URLs after browser refresh using authenticated encryption of tokens at rest.
* Copy the correct URL from each individual invitation card; no plain-text invitation secrets are saved.
* Immediately erase the encrypted secret when the link is used up, revoked or expires during cleanup.
* Existing previously-created one-way-hashed links cannot be recovered retrospectively.
* Improve email OTP send diagnostics, retry behavior and 45-second resend cooldown. Failed outgoing mail does not consume the three-accepted-sends quota.
* Preserve earlier valid OTP if a resend fails, and allow its entry when still pending.
* SMTP configuration remains a separate requirement; test with GoSMTP and inspect recipient mailbox / provider logs.

= 1.14.0 =
* Per-link responsive Expiry Manager: remaining time, new time, change preview and precise shortening or extension.
* Relative durations from now or added to current expiration; preset, custom and site-timezone exact date options.
* Hardened server-side revalidation, nonce protection and card-specific confirmation.
* Security Center now includes practical SMTP delivery troubleshooting steps.


= 1.13.0 =
* Emergency Lock immediately revokes active invitations/sessions and suspends new access until manually unlocked; old links do not revive.
* Enhanced temporary-user activity log with limited metadata for content, plugins, themes, user roles and sensitive site configuration changes.
* Optional best-effort email security alerts (throttled), defaulting to WordPress admin email.
* Site email/SMTP diagnostic test (WordPress mail acceptance, not verified delivery).
* Optional eight-digit email OTP challenge (10-minute expiry, five attempts, three sends/15 minutes per invitation), disabled by default.
* Preserve original WordPress role, sidebar and Custom Feature Locks.


= 1.12.0 =
* Add owner-only Custom Feature Locks to individual invitation cards.
* Support multiple core WordPress permission groups and advanced registered Administrator capability locks.
* Do not change WordPress roles or the original Dashboard. No locks by default.
* Retain OneClicky self-protection and session expiry/revoke logic.


= 1.11.0 =
* Restore genuine WordPress roles for new invitations.
* Migrate existing valid Administrator invitations from the deprecated restricted role.
* Remove the Permission Manager panel, restricted capability filters and imitation locked sidebar behavior.
* Hide OneClicky plugin row and reject normal changes to OneClicky itself from temporary accounts.
* Preserve existing invitation management, expiry, revoke, restore and status features.

= 1.10.0 =
* Native WordPress dashboard with restricted capability controls.
