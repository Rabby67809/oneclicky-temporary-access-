<?php
/** Owner emergency switch, audit hooks, privacy-aware security alerts and mail diagnostics. */
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class AMTA_Guard {
    public static function init() {
        add_action( 'wp_after_insert_post', array( __CLASS__, 'post_change' ), 10, 4 );
        add_action( 'deleted_post', array( __CLASS__, 'post_deleted' ), 10, 2 );
        add_action( 'activated_plugin', array( __CLASS__, 'plugin_activated' ), 10, 1 );
        add_action( 'deactivated_plugin', array( __CLASS__, 'plugin_deactivated' ), 10, 1 );
        add_action( 'set_user_role', array( __CLASS__, 'role_changed' ), 10, 3 );
        add_action( 'user_register', array( __CLASS__, 'user_created' ), 10, 1 );
        add_action( 'switch_theme', array( __CLASS__, 'theme_changed' ), 10, 1 );
        add_action( 'updated_option', array( __CLASS__, 'option_changed' ), 10, 3 );
    }

    public static function locked() { return (bool) get_option( 'amta_emergency_lockdown', false ); }

    public static function owner() {
        return is_user_logged_in() && ! AMTA_Hardening::is_temporary( get_current_user_id() ) && current_user_can( 'manage_options' );
    }

    public static function access_id() {
        $uid = get_current_user_id();
        if ( ! $uid ) { return 0; }
        $id = (int) get_user_meta( $uid, 'amta_access_id', true );
        if ( ! $id || ! AMTA_Storage::is_live( AMTA_Storage::get_for_user( $uid, $id ) ) ) { return 0; }
        return $id;
    }

    public static function audit( $event, $details = array(), $sensitive = false ) {
        $id = self::access_id();
        if ( ! $id ) { return; }
        AMTA_Storage::log( $id, $event, get_current_user_id(), $details );
        if ( $sensitive ) { self::alert( $event, $id, $details ); }
    }

    public static function post_change( $post_id, $post, $update, $post_before ) {
        if ( ! $post || wp_is_post_revision( $post_id ) || wp_is_post_autosave( $post_id ) || ! in_array( $post->post_type, array( 'post', 'page' ), true ) ) { return; }
        self::audit( 'content_changed', array( 'post_id' => absint( $post_id ), 'type' => sanitize_key( $post->post_type ), 'action' => $update ? 'updated' : 'created' ) );
    }

    public static function post_deleted( $post_id, $post ) {
        if ( $post && in_array( $post->post_type, array( 'post', 'page' ), true ) ) {
            self::audit( 'content_deleted', array( 'post_id' => absint( $post_id ), 'type' => sanitize_key( $post->post_type ) ), true );
        }
    }

    public static function plugin_activated( $file ) {
        self::audit( 'plugin_enabled', array( 'plugin' => sanitize_text_field( $file ) ), true );
    }

    public static function plugin_deactivated( $file ) {
        self::audit( 'plugin_disabled', array( 'plugin' => sanitize_text_field( $file ) ), true );
    }

    public static function role_changed( $uid, $role, $old_roles ) {
        // Do not log initial OneClicky account role setup; it is already covered by 'created'.
        self::audit( 'role_changed', array( 'user_id' => absint( $uid ), 'role' => sanitize_key( $role ) ), true );
    }

    public static function user_created( $uid ) {
        self::audit( 'user_created', array( 'user_id' => absint( $uid ) ), true );
    }

    public static function theme_changed( $name ) {
        self::audit( 'theme_switched', array( 'theme' => sanitize_text_field( $name ) ), true );
    }

    public static function option_changed( $option, $old, $new ) {
        $watched = array( 'siteurl', 'home', 'users_can_register', 'default_role', 'permalink_structure', 'blog_public' );
        if ( in_array( $option, $watched, true ) ) {
            // Log the OPTION NAME, never its before/after values (potential secrets).
            self::audit( 'site_setting', array( 'option' => $option ), true );
        }
    }

    /** Email is best-effort only. Throttle by invitation/event to reduce noise. */
    public static function alert( $event, $access_id, $details = array() ) {
        if ( '0' === (string) get_option( 'amta_security_alerts', '1' ) ) { return false; }
        $email = get_option( 'admin_email' );
        if ( ! is_email( $email ) ) { return false; }
        $key = 'amta_alert_' . md5( $event . '|' . absint( $access_id ) );
        if ( get_transient( $key ) ) { return false; }
        set_transient( $key, 1, 300 );
        $subject = sprintf( '[%s] OneClicky security notice', wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) );
        $body = sprintf( "OneClicky security event: %s\nInvitation ID: %d\nTime (UTC): %s\n\nReview the activity inside WordPress > OneClicky > Activity.\nNo invitation tokens or passwords are included.", sanitize_key( $event ), absint( $access_id ), gmdate( 'Y-m-d H:i:s' ) );
        return (bool) wp_mail( $email, $subject, $body, array( 'Content-Type: text/plain; charset=UTF-8' ) );
    }

    public static function handle_emergency() {
        if ( ! self::owner() || ! current_user_can( 'create_users' ) || ! current_user_can( 'promote_users' ) ) {
            wp_die( esc_html__( 'Not authorized.', 'oneclicky-temporary-access' ), '', array( 'response' => 403 ) );
        }
        check_admin_referer( 'amta_emergency', 'amta_nonce' );
        $mode = isset( $_POST['amta_mode'] ) && is_string( $_POST['amta_mode'] ) ? sanitize_key( wp_unslash( $_POST['amta_mode'] ) ) : '';
        if ( 'enable' === $mode ) {
            update_option( 'amta_emergency_lockdown', time(), false );
            AMTA_Storage::revoke_all();
            AMTA_Storage::log( 0, 'emergency_on', get_current_user_id() );
            self::alert( 'emergency_on', 0 );
            $notice = 'emergency_on';
        } elseif ( 'disable' === $mode ) {
            // Fail closed: no previously live invitations may revive upon unlocking.
            AMTA_Storage::revoke_all();
            global $wpdb;
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Access state and logs are read from custom plugin tables; revocations must not be masked by stale object-cache values.
            $remaining = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE status = 'active'", AMTA_Storage::table() ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Lockdown is security-sensitive and must check the live plugin-owned table.
            if ( $remaining ) { $notice = 'emergency_failed'; }
            else {
                delete_option( 'amta_emergency_lockdown' );
                AMTA_Storage::log( 0, 'emergency_off', get_current_user_id() );
                $notice = 'emergency_off';
            }
        } else {
            wp_die( esc_html__( 'Invalid request.', 'oneclicky-temporary-access' ), '', array( 'response' => 400 ) );
        }
        wp_safe_redirect( add_query_arg( 'amta_notice', $notice, admin_url( 'admin.php?page=oneclicky-temporary-access&view=security' ) ) );
        exit;
    }

    public static function handle_alert_settings() {
        if ( ! self::owner() ) { wp_die( 'Forbidden', '', array( 'response' => 403 ) ); }
        check_admin_referer( 'amta_alert_settings', 'amta_nonce' );
        update_option( 'amta_security_alerts', isset( $_POST['amta_alerts_enabled'] ) ? '1' : '0', false );
        wp_safe_redirect( add_query_arg( 'amta_notice', 'settings_saved', admin_url( 'admin.php?page=oneclicky-temporary-access&view=security' ) ) );
        exit;
    }

    public static function handle_mail_test() {
        if ( ! self::owner() ) { wp_die( 'Forbidden', '', array( 'response' => 403 ) ); }
        check_admin_referer( 'amta_mail_test', 'amta_nonce' );
        // Never accept an arbitrary relay address from POST. Deliver only to the site owner address.
        $email = get_option( 'admin_email' );
        $sent = is_email( $email ) && wp_mail( $email, '[OneClicky] WordPress email delivery test', "This is a test email from your OneClicky plugin.\nIf you received it, WordPress mail transport is working for this message.\nThis does not guarantee all future delivery.", array( 'Content-Type: text/plain; charset=UTF-8' ) );
        wp_safe_redirect( add_query_arg( 'amta_notice', $sent ? 'mail_accepted' : 'mail_failed', admin_url( 'admin.php?page=oneclicky-temporary-access&view=security' ) ) );
        exit;
    }
}
