<?php
/**
 * Plugin Name: OneClicky – Temporary Access & Guard Control
 * Description: Issue time-limited invitation logins with optional email verification, instant revocation, access safeguards and a local audit trail.
 * Version: 1.16.0
 * Requires at least: 6.2
 * Requires PHP: 7.4
 * Author: Rejoyan9009
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: oneclicky-temporary-access
 * Domain Path: /languages
 *
 * @package OneClickyTemporaryAccess
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'AMTA_VERSION', '1.16.0' );
define( 'AMTA_FILE', __FILE__ );
define( 'AMTA_PATH', plugin_dir_path( __FILE__ ) );
define( 'AMTA_URL', plugin_dir_url( __FILE__ ) );

require_once AMTA_PATH . 'includes/class-amta-storage.php';
require_once AMTA_PATH . 'includes/class-amta-security.php';
require_once AMTA_PATH . 'includes/class-amta-vault.php';
require_once AMTA_PATH . 'includes/class-amta-otp.php';
require_once AMTA_PATH . 'includes/class-amta-guard.php';
require_once AMTA_PATH . 'includes/class-amta-hardening.php';
require_once AMTA_PATH . 'includes/class-amta-unlock.php';
require_once AMTA_PATH . 'includes/class-amta-access-locks.php';
require_once AMTA_PATH . 'includes/class-amta-presence.php';
require_once AMTA_PATH . 'includes/class-amta-creator.php';
require_once AMTA_PATH . 'includes/class-amta-admin.php';

register_activation_hook( __FILE__, array( 'AMTA_Storage', 'install' ) );
register_deactivation_hook( __FILE__, array( 'AMTA_Storage', 'deactivate' ) );

add_action( 'plugins_loaded', 'amta_initialize' );

/** Bootstrap the plugin. */
function amta_initialize() {
    add_action( 'init', array( 'AMTA_Storage', 'maybe_upgrade' ), 5 );
    AMTA_Hardening::init();
    AMTA_Access_Locks::init();
    AMTA_Security::init();
    AMTA_Presence::init();
    AMTA_Guard::init();
    if ( is_admin() ) {
        AMTA_Admin::init();
    }
    add_action( 'amta_cleanup', array( 'AMTA_Storage', 'cleanup' ) );
    add_filter( 'plugin_action_links_' . plugin_basename( AMTA_FILE ), 'amta_settings_link' );
}

/** Add an easy-to-find entry point. */
function amta_settings_link( $links ) {
    if ( ! AMTA_Hardening::is_temporary( get_current_user_id() ) && current_user_can( 'manage_options' ) ) {
        array_unshift( $links, '<a href="' . esc_url( admin_url( 'admin.php?page=oneclicky-temporary-access' ) ) . '">' . esc_html__( 'Manage access', 'oneclicky-temporary-access' ) . '</a>' );
    }
    return $links;
}
