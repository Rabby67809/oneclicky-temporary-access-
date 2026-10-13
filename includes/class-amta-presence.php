<?php
/** Anonymous-safe labels and lightweight authenticated dashboard-presence tracking. */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class AMTA_Presence {
    const ONLINE_WINDOW = 180; // Three minutes since a genuine, foreground interaction.

    public static function init() {
        // load-index.php fires only for the actual authenticated WP dashboard,
        // never for an invite GET, login link POST, cron, REST, or AJAX call.
        add_action( 'load-index.php', array( __CLASS__, 'dashboard_opened' ) );
        add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_client' ) );
        add_action( 'wp_ajax_amta_presence_ping', array( __CLASS__, 'ping' ) );
        add_action( 'wp_ajax_amta_presence_statuses', array( __CLASS__, 'statuses' ) );
    }

    /** Returns a valid OneClicky account record for the current logged-in user. */
    private static function own_record() {
        $user_id = get_current_user_id();
        if ( $user_id <= 0 ) {
            return null;
        }
        $access_id = absint( get_user_meta( $user_id, 'amta_access_id', true ) );
        if ( ! $access_id ) {
            return null;
        }
        $record = AMTA_Storage::get_for_user( $user_id, $access_id );
        return AMTA_Storage::is_live( $record ) ? $record : null;
    }

    public static function dashboard_opened() {
        $record = self::own_record();
        if ( $record && current_user_can( 'read' ) ) {
            AMTA_Storage::mark_dashboard_entered( $record->id, $record->user_id );
        }
    }

    public static function enqueue_client( $hook ) {
        // It runs on all admin screens visited by the temporary user, but
        // only starts AFTER an actual WP dashboard visit has been recorded.
        $record = self::own_record();
        if ( ! $record || ! (int) $record->dashboard_entered_at ) {
            // The database value can be cached on a request where
            // dashboard_opened just set it; enqueue on the dashboard too.
            if ( ! $record || 'index.php' !== $hook ) {
                return;
            }
        }
        wp_enqueue_script( 'amta-presence-client', AMTA_URL . 'assets/js/presence.js', array(), AMTA_VERSION, true );
        wp_localize_script( 'amta-presence-client', 'amtaPresence', array(
            'url' => admin_url( 'admin-ajax.php' ),
            'nonce' => wp_create_nonce( 'amta_presence_ping' ),
        ) );
    }

    public static function ping() {
        if ( ! check_ajax_referer( 'amta_presence_ping', 'nonce', false ) ) {
            wp_send_json_error( array( 'message' => 'Invalid request.' ), 403 );
        }
        $record = self::own_record();
        if ( ! $record || ! (int) $record->dashboard_entered_at || ! current_user_can( 'read' ) ) {
            wp_send_json_error( array( 'message' => 'Session unavailable.' ), 403 );
        }
        AMTA_Storage::ping_presence( (int) $record->id, (int) $record->user_id );
        wp_send_json_success( array( 'ok' => true ) );
    }

    /** Conservative, truthful server-rendered state (uses no IP, URL, or keystroke history). */
    public static function state( $record, $now = null ) {
        $now = null === $now ? time() : (int) $now;
        if ( ! $record ) {
            return array( 'code' => 'deleted', 'label' => __( 'Deleted', 'oneclicky-temporary-access' ), 'detail' => __( 'Invitation unavailable.', 'oneclicky-temporary-access' ) );
        }
        if ( 'revoked' === $record->status ) {
            return array( 'code' => 'revoked', 'label' => __( 'Revoked', 'oneclicky-temporary-access' ), 'detail' => __( 'All temporary sessions have been terminated.', 'oneclicky-temporary-access' ) );
        }
        if ( 'expired' === $record->status || (int) $record->expires_at <= $now ) {
            return array( 'code' => 'expired', 'label' => __( 'Expired', 'oneclicky-temporary-access' ), 'detail' => __( 'This invitation is no longer valid.', 'oneclicky-temporary-access' ) );
        }
        if ( 'active' !== $record->status ) {
            return array( 'code' => 'active', 'label' => __( 'Unavailable', 'oneclicky-temporary-access' ), 'detail' => __( 'This invitation cannot be used.', 'oneclicky-temporary-access' ) );
        }
        if ( empty( $record->dashboard_entered_at ) ) {
            return array(
                'code' => 'pending',
                'label' => __( 'Pending', 'oneclicky-temporary-access' ),
                'detail' => (int) $record->uses > 0
                    ? __( 'Link confirmed; waiting for the recipient to reach the dashboard.', 'oneclicky-temporary-access' )
                    : __( 'Waiting for the recipient to sign in and open the dashboard.', 'oneclicky-temporary-access' ),
            );
        }
        $last_seen = (int) $record->last_seen_at;
        if ( $last_seen > 0 && $last_seen <= $now && $last_seen >= $now - self::ONLINE_WINDOW ) {
            return array(
                'code' => 'working',
                'label' => __( 'Active & Working', 'oneclicky-temporary-access' ),
                'detail' => __( 'Dashboard reached; browser activity detected recently.', 'oneclicky-temporary-access' ),
            );
        }
        $elapsed = max( 60, $now - max( 1, $last_seen ) );
        $minutes = max( 1, (int) ceil( $elapsed / MINUTE_IN_SECONDS ) );
        return array(
            'code' => 'idle',
            'label' => __( 'Active · Idle', 'oneclicky-temporary-access' ),
            'detail' => sprintf(
                /* translators: %d: minutes since activity */
                _n( 'Dashboard visited; last activity about %d minute ago.', 'Dashboard visited; last activity about %d minutes ago.', $minutes, 'oneclicky-temporary-access' ),
                $minutes
            ),
        );
    }

    /** Admin polling is read-only, authorized, nonce-protected, and bounded. */
    public static function statuses() {
        if ( AMTA_Hardening::is_temporary( get_current_user_id() ) || ! current_user_can( 'manage_options' ) || ! check_ajax_referer( 'amta_presence_statuses', 'nonce', false ) ) {
            wp_send_json_error( array( 'message' => 'Not allowed.' ), 403 );
        }
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Filter to scalars and normalize every ID with absint immediately below.
        $raw_ids = isset( $_POST['ids'] ) && is_array( $_POST['ids'] ) ? wp_unslash( $_POST['ids'] ) : array();
        if ( count( $raw_ids ) > 20 ) {
            wp_send_json_error( array( 'message' => 'Too many invitations.' ), 400 );
        }
        $ids = array_unique( array_filter( array_map( 'absint', array_filter( $raw_ids, 'is_scalar' ) ) ) );
        $states = array();
        foreach ( $ids as $id ) {
            $states[ (string) $id ] = self::state( AMTA_Storage::get( $id ) );
        }
        nocache_headers();
        wp_send_json_success( array( 'states' => $states ) );
    }
}
