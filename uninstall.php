<?php
/** Uninstall only plugin-owned data; preserve authored content and its user references. */
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

global $wpdb;
$amta_sites = is_multisite() ? get_sites( array( 'fields' => 'ids', 'number' => 0 ) ) : array( get_current_blog_id() );

foreach ( $amta_sites as $amta_site_id ) {
    if ( is_multisite() ) {
        switch_to_blog( (int) $amta_site_id );
    }
    $amta_links = $wpdb->prefix . 'amta_links';
    $amta_events = $wpdb->prefix . 'amta_events';
    $amta_removed = $wpdb->prefix . 'amta_removed';
    // Query table names are derived solely from WordPress's trusted prefix.
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Access state and logs are read from custom plugin tables; revocations must not be masked by stale object-cache values.
    $amta_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $amta_links ) ) );
    if ( $amta_exists === $amta_links ) {
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Access state and logs are read from custom plugin tables; revocations must not be masked by stale object-cache values.
        $amta_rows = $wpdb->get_results( $wpdb->prepare( 'SELECT id, user_id FROM %i', $amta_links ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Query plugin-owned custom table during uninstall; no core API exists.
        foreach ( $amta_rows as $amta_row ) {
            if ( (int) get_user_meta( (int) $amta_row->user_id, 'amta_access_id', true ) !== (int) $amta_row->id ) {
                continue;
            }
            $amta_user = get_userdata( (int) $amta_row->user_id );
            if ( $amta_user ) {
                WP_Session_Tokens::get_instance( (int) $amta_row->user_id )->destroy_all();
                $amta_user->set_role( '' );
            }
            delete_user_meta( (int) $amta_row->user_id, 'amta_access_id' );
            delete_user_meta( (int) $amta_row->user_id, 'amta_recipient_email' );
            delete_user_meta( (int) $amta_row->user_id, 'amta_require_otp' );
            delete_user_meta( (int) $amta_row->user_id, 'amta_permission_unlock' );
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Only uninstall cleans up OneClicky-owned tables; schema changes cannot use a core CRUD API.
        $wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $amta_links ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall exclusively removes plugin-owned custom tables.
    }
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Only uninstall cleans up OneClicky-owned tables; schema changes cannot use a core CRUD API.
    $wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $amta_events ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall exclusively removes plugin-owned custom tables.
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Only uninstall cleans up OneClicky-owned tables; schema changes cannot use a core CRUD API.
    $wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $amta_removed ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall exclusively removes plugin-owned custom tables.
    delete_option( 'amta_db_version' );
    delete_option( 'amta_security_migration' );
    delete_option( 'amta_emergency_lockdown' );
    delete_option( 'amta_security_alerts' );
    // Keep the reduced-privilege role if disabled accounts still have authored content.
    // Never restore administrator capabilities during uninstall.
    wp_clear_scheduled_hook( 'amta_cleanup' );
    if ( is_multisite() ) {
        restore_current_blog();
    }
}
