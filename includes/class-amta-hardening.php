<?php
/** Restore genuine WordPress roles while discouraging changes to OneClicky itself.
 * IMPORTANT: a real Administrator can bypass plugin-level checks by executing PHP,
 * installing other plugins, editing server files, or modifying the database.
 * This is only a guard against ordinary WordPress UI/API actions, not isolation.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class AMTA_Hardening {
    // Kept for migration from versions 1.6 through 1.10.0.
    const ROLE = 'amta_restricted_admin';
    const MIGRATION_VERSION = '1.11.0';

    public static function init() {
        add_action( 'init', array( __CLASS__, 'restore_legacy_admin_roles' ), 10 );
        add_action( 'admin_menu', array( __CLASS__, 'hide_admin_menus' ), 999 );
        add_action( 'admin_init', array( __CLASS__, 'block_oneclicky_admin_routes' ), 1 );
        add_action( 'admin_init', array( __CLASS__, 'redirect_old_workspace_links' ), 2 );
        add_action( 'admin_init', array( __CLASS__, 'block_oneclicky_plugin_actions' ), 3 );
        add_filter( 'all_plugins', array( __CLASS__, 'hide_oneclicky_plugin_row' ), 999 );
        add_filter( 'plugin_action_links', array( __CLASS__, 'restrict_plugin_row_actions' ), 999, 2 );
        add_filter( 'pre_update_option_active_plugins', array( __CLASS__, 'protect_plugin_active_state' ), 999, 2 );
        add_filter( 'pre_update_site_option_active_sitewide_plugins', array( __CLASS__, 'protect_plugin_active_state' ), 999, 2 );
        add_filter( 'rest_pre_dispatch', array( __CLASS__, 'protect_plugin_rest' ), 1, 3 );
        add_action( 'admin_init', array( __CLASS__, 'protect_plugin_ajax_actions' ), 1 );
        add_filter( 'update_user_metadata', array( __CLASS__, 'guard_user_meta' ), 999, 5 );
        add_filter( 'add_user_metadata', array( __CLASS__, 'guard_user_meta' ), 999, 5 );
        add_filter( 'delete_user_metadata', array( __CLASS__, 'guard_user_meta' ), 999, 5 );
    }

    public static function is_temporary( $user_id ) {
        return (int) $user_id > 0 && absint( get_user_meta( (int) $user_id, 'amta_access_id', true ) ) > 0;
    }

    /** No remapping: every requested WordPress role behaves as WordPress defines it. */
    public static function safe_role( $role ) { return $role; }

    public static function role_label( $role, $fallback = '' ) {
        return $fallback;
    }

    /** Restore ONLY live invitations that originally requested administrator.
     * Never elevate Editors, Authors, expired/revoked users, or non-OneClicky accounts.
     */
    public static function restore_legacy_admin_roles() {
        if ( get_option( 'amta_role_restoration_version' ) === self::MIGRATION_VERSION ) { return; }
        global $wpdb;
        $table = AMTA_Storage::table();
        $cursor = 0;
        $now = time();
        do {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Access state and logs are read from custom plugin tables; revocations must not be masked by stale object-cache values.
            $rows = $wpdb->get_results( $wpdb->prepare(
                "SELECT id, user_id FROM %i WHERE role = %s AND status = %s AND expires_at > %d AND id > %d ORDER BY id ASC LIMIT 100",
                $table, 'administrator', 'active', $now, $cursor
            ) );
            if ( ! is_array( $rows ) ) { return; }
            foreach ( $rows as $row ) {
                $cursor = (int) $row->id;
                $user_id = (int) $row->user_id;
                if ( (int) get_user_meta( $user_id, 'amta_access_id', true ) !== (int) $row->id ) { continue; }
                $user = get_userdata( $user_id );
                if ( $user && in_array( self::ROLE, (array) $user->roles, true ) ) {
                    $user->set_role( 'administrator' );
                }
                // Discard prior restricted-role grants and custom content policies.
                delete_user_meta( $user_id, AMTA_Unlock::META_KEY );
                delete_user_meta( $user_id, AMTA_Unlock::POLICY_KEY );
            }
        } while ( count( $rows ) === 100 );
        update_option( 'amta_role_restoration_version', self::MIGRATION_VERSION, false );
    }

    public static function hide_admin_menus() {
        if ( self::is_temporary( get_current_user_id() ) ) {
            remove_menu_page( 'oneclicky-temporary-access' );
        }
    }

    public static function is_oneclicky_plugin( $plugin ) {
        if ( ! is_string( $plugin ) ) { return false; }
        $target = ltrim( wp_normalize_path( rawurldecode( $plugin ) ), '/' );
        $actual = plugin_basename( AMTA_FILE );
        return $target === $actual || $target === substr( $actual, 0, -4 );
    }

    /** OneClicky's administration is private, even for full Administrator invitations. */
    public static function block_oneclicky_admin_routes() {
        if ( ! self::is_temporary( get_current_user_id() ) ) { return; }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only inspection of WordPress core navigation/targets. Core actions verify their own nonces.
        if ( isset( $_REQUEST['page'] ) && is_scalar( $_REQUEST['page'] ) &&
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only inspection of WordPress core navigation/targets. Core actions verify their own nonces.
            'oneclicky-temporary-access' === sanitize_key( wp_unslash( $_REQUEST['page'] ) ) ) {
            wp_die( esc_html__( 'OneClicky access controls are reserved for the site owner.', 'oneclicky-temporary-access' ), '', array( 'response' => 403 ) );
        }
        // No special restriction on original WordPress dashboard/admin screens.
    }

    public static function redirect_old_workspace_links() {
        if ( ! self::is_temporary( get_current_user_id() ) ||
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only inspection of WordPress core navigation/targets. Core actions verify their own nonces.
             ! isset( $_GET['page'] ) || ! is_scalar( $_GET['page'] ) ) { return; }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only inspection of WordPress core navigation/targets. Core actions verify their own nonces.
        $slug = sanitize_key( wp_unslash( $_GET['page'] ) );
        if ( 'amta-workspace' === $slug || 0 === strpos( $slug, 'amta-gate-' ) || 0 === strpos( $slug, 'amta-locked-' ) ) {
            wp_safe_redirect( admin_url( 'index.php' ), 302 );
            exit;
        }
    }

    /** Avoid core update/deactivation/deletion/edit UI when OneClicky is the target.
     * Ordinary actions for ALL OTHER plugins retain original Administrator access.
     */
    public static function block_oneclicky_plugin_actions() {
        if ( ! self::is_temporary( get_current_user_id() ) ) { return; }
        global $pagenow;
        if ( ! in_array( $pagenow, array( 'plugins.php', 'plugin-editor.php', 'plugin-install.php', 'update.php', 'update-core.php', 'admin-ajax.php' ), true ) ) { return; }
        $targets = array();
        foreach ( array( 'plugin', 'file', 'checked', 'plugins' ) as $field ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only inspection of WordPress core navigation/targets. Core actions verify their own nonces.
            if ( ! isset( $_REQUEST[ $field ] ) ) { continue; }
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Read-only target inspection; each scalar is sanitized before matching and WordPress validates the actual action nonce.
            $raw = wp_unslash( $_REQUEST[ $field ] );
            foreach ( (array) $raw as $item ) {
                if ( is_string( $item ) ) { $targets[] = sanitize_text_field( $item ); }
            }
        }
        foreach ( $targets as $target ) {
            if ( self::is_oneclicky_plugin( $target ) ||
                 // Plugin editor can specify an internal file as the edited path.
                 ( 'plugin-editor.php' === $pagenow && 0 === strpos( wp_normalize_path( $target ), 'oneclicky-temporary-access/' ) ) ) {
                wp_die( esc_html__( 'OneClicky cannot be changed through this WordPress account.', 'oneclicky-temporary-access' ), '', array( 'response' => 403 ) );
            }
        }
    }

    /** API plugin mutations targeting OneClicky; other plugins stay available. */
    public static function protect_plugin_rest( $result, $server, $request ) {
        if ( ! self::is_temporary( get_current_user_id() ) || ! is_object( $request ) ||
             ! method_exists( $request, 'get_route' ) || ! method_exists( $request, 'get_method' ) ) { return $result; }
        $route = rawurldecode( (string) $request->get_route() );
        $method = strtoupper( (string) $request->get_method() );
        if ( preg_match( '~^/wp/v2/plugins(?:/|$)~', $route ) &&
             ! in_array( $method, array( 'GET', 'HEAD', 'OPTIONS' ), true ) &&
             ( false !== strpos( $route, plugin_basename( AMTA_FILE ) ) ||
               false !== strpos( $route, substr( plugin_basename( AMTA_FILE ), 0, -4 ) ) ) ) {
            return new WP_Error( 'amta_self_protected', __( 'OneClicky cannot be changed using this account.', 'oneclicky-temporary-access' ), array( 'status' => 403 ) );
        }
        return $result;
    }

    public static function protect_plugin_ajax_actions() {
        // WordPress invokes admin_init for admin-ajax.php. Reject only explicitly
        // targeted OneClicky operations, not other plugin actions.
        if ( ! self::is_temporary( get_current_user_id() ) ||
             ! function_exists( 'wp_doing_ajax' ) || ! wp_doing_ajax() ) { return; }
        self::block_oneclicky_plugin_actions();
    }

    /** Protect activation option list without interfering with other plugins. */
    public static function protect_plugin_active_state( $new, $old ) {
        if ( ! self::is_temporary( get_current_user_id() ) || ! is_array( $new ) || ! is_array( $old ) ) { return $new; }
        $basename = plugin_basename( AMTA_FILE );
        if ( amta_array_is_list_compat( $old ) ) {
            if ( in_array( $basename, $old, true ) && ! in_array( $basename, $new, true ) ) {
                $new[] = $basename;
            }
        } elseif ( isset( $old[ $basename ] ) && ! isset( $new[ $basename ] ) ) {
            $new[ $basename ] = $old[ $basename ];
        }
        return $new;
    }

    public static function hide_oneclicky_plugin_row( $plugins ) {
        if ( self::is_temporary( get_current_user_id() ) && is_array( $plugins ) ) {
            unset( $plugins[ plugin_basename( AMTA_FILE ) ] );
        }
        return $plugins;
    }

    public static function restrict_plugin_row_actions( $actions, $plugin_file ) {
        if ( self::is_temporary( get_current_user_id() ) && self::is_oneclicky_plugin( $plugin_file ) ) {
            unset( $actions['activate'], $actions['deactivate'], $actions['delete'], $actions['edit'], $actions['update'] );
        }
        return $actions;
    }

    /** Prevent invited Administrators from erasing their OneClicky identity. */
    public static function guard_user_meta( $check, $object_id, $meta_key, $value, $extra = null ) {
        if ( null !== $check || ! self::is_temporary( get_current_user_id() ) || ! is_string( $meta_key ) ) { return $check; }
        if ( in_array( $meta_key, array( 'amta_access_id', 'amta_recipient_email', AMTA_Unlock::META_KEY, AMTA_Unlock::POLICY_KEY, AMTA_Access_Locks::META_KEY ), true ) ||
             ( (int) $object_id === get_current_user_id() && preg_match( '/_(?:capabilities|user_level)\z/', $meta_key ) ) ) {
            return false;
        }
        return $check;
    }
}

/** PHP 7.4 compatible sequential-array check for site/sitewide plugin options. */
function amta_array_is_list_compat( $items ) {
    return array_keys( $items ) === range( 0, count( $items ) - 1 ) || array() === $items;
}
