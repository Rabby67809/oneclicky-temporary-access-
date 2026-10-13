<?php
/** Short-lived, owner-managed capability grants, one expiration per permission. */
if ( ! defined( 'ABSPATH' ) ) { exit; }
final class AMTA_Unlock {
    const META_KEY = 'amta_permission_unlock';
    const MAX_MINUTES = 60;

    const POLICY_KEY = 'amta_custom_cap_policy';
    const MAX_PLUGINS = 12;

    /** Explicit allowlist; file/code management and privilege escalation stay prohibited. */
    public static function scopes() {
        return array(
            'posts_edit' => array( 'label' => __( 'Posts: read and edit', 'oneclicky-temporary-access' ),
                'caps' => array( 'edit_posts', 'edit_others_posts', 'edit_published_posts', 'edit_private_posts', 'read_private_posts' ) ),
            'posts_publish' => array( 'label' => __( 'Posts: publish', 'oneclicky-temporary-access' ),
                'caps' => array( 'publish_posts' ) ),
            'posts_delete' => array( 'label' => __( 'Posts: delete', 'oneclicky-temporary-access' ),
                'caps' => array( 'delete_posts', 'delete_others_posts', 'delete_published_posts', 'delete_private_posts' ) ),
            'pages_edit' => array( 'label' => __( 'Pages: read and edit', 'oneclicky-temporary-access' ),
                'caps' => array( 'edit_pages', 'edit_others_pages', 'edit_published_pages', 'edit_private_pages', 'read_private_pages' ) ),
            'pages_publish' => array( 'label' => __( 'Pages: publish', 'oneclicky-temporary-access' ),
                'caps' => array( 'publish_pages' ) ),
            'pages_delete' => array( 'label' => __( 'Pages: delete', 'oneclicky-temporary-access' ),
                'caps' => array( 'delete_pages', 'delete_others_pages', 'delete_published_pages', 'delete_private_pages' ) ),
            'media' => array( 'label' => __( 'Media: upload and edit attachments', 'oneclicky-temporary-access' ),
                'caps' => array( 'upload_files' ) ),
            'comments' => array( 'label' => __( 'Comments: moderate', 'oneclicky-temporary-access' ),
                'caps' => array( 'moderate_comments' ) ),
            'categories' => array( 'label' => __( 'Categories and taxonomies', 'oneclicky-temporary-access' ),
                'caps' => array( 'manage_categories' ) ),
            'appearance' => array( 'label' => __( 'Appearance: menus, widgets, Customizer', 'oneclicky-temporary-access' ),
                'caps' => array( 'edit_theme_options', 'customize' ) ),
            'users_view' => array( 'label' => __( 'Users: view list (read-only)', 'oneclicky-temporary-access' ),
                'caps' => array( 'list_users' ) ),
            'tools_export' => array( 'label' => __( 'Tools: export content (sensitive)', 'oneclicky-temporary-access' ),
                'caps' => array( 'export' ) ),
            'plugin_toggle' => array( 'label' => __( 'Plugins: activate/deactivate selected installed plugins', 'oneclicky-temporary-access' ),
                'caps' => array( 'activate_plugins', 'deactivate_plugins' ) ),
        );
    }

    /** Managed content grants only apply to Protected Admin, not other WordPress roles. */
    public static function managed_core_caps() {
        $caps = array();
        foreach ( self::scopes() as $scope => $config ) {
            if ( in_array( $scope, array( 'posts_edit', 'posts_publish', 'posts_delete', 'pages_edit', 'pages_publish', 'pages_delete', 'media', 'comments', 'categories' ), true ) ) {
                $caps = array_merge( $caps, $config['caps'] );
            }
        }
        return array_values( array_unique( $caps ) );
    }
    public static function custom_policy_enabled( $user_id ) {
        $stored = get_user_meta( (int) $user_id, self::POLICY_KEY, true );
        return is_array( $stored ) && ! empty( $stored['enabled'] ) &&
            absint( $stored['access_id'] ) === absint( get_user_meta( (int) $user_id, 'amta_access_id', true ) );
    }
    /** Individual expiry checks, invitation binding, legacy single-grant compatibility. */
    public static function grant_for_user( $user_id, $now = null ) {
        $user_id = absint( $user_id );
        $now = null === $now ? time() : (int) $now;
        if ( ! $user_id || ! AMTA_Hardening::is_temporary( $user_id ) ) { return null; }
        $stored = get_user_meta( $user_id, self::META_KEY, true );
        if ( ! is_array( $stored ) || ! isset( $stored['access_id'] ) ||
            absint( $stored['access_id'] ) !== absint( get_user_meta( $user_id, 'amta_access_id', true ) ) ) { return null; }
        $record = AMTA_Storage::get_for_user( $user_id, absint( $stored['access_id'] ) );
        if ( ! $record || 'active' !== $record->status || (int) $record->expires_at <= $now ) { return null; }
        $entries = isset( $stored['grants'] ) && is_array( $stored['grants'] ) ? $stored['grants'] : array();
        if ( ! $entries && isset( $stored['scope'], $stored['expires_at'] ) ) {
            $entries = array( $stored['scope'] => array(
                'expires_at' => $stored['expires_at'],
                'plugin' => isset( $stored['plugin'] ) ? $stored['plugin'] : '',
                'actor' => isset( $stored['actor'] ) ? $stored['actor'] : 0,
                'plugins' => isset( $stored['plugins'] ) ? $stored['plugins'] : array(),
            ) );
        }
        $valid = array();
        foreach ( $entries as $scope => $entry ) {
            if ( ! is_string( $scope ) || ! isset( self::scopes()[ $scope ] ) || ! is_array( $entry ) || ! isset( $entry['expires_at'] ) ) { continue; }
            $end = (int) $entry['expires_at'];
            if ( $end <= $now || $end > $now + self::MAX_MINUTES * MINUTE_IN_SECONDS || $end > (int) $record->expires_at ) { continue; }
            if ( 'plugin_toggle' === $scope ) {
                $plugins = isset( $entry['plugins'] ) && is_array( $entry['plugins'] ) ? $entry['plugins'] : array();
                if ( ! $plugins && ! empty( $entry['plugin'] ) && is_string( $entry['plugin'] ) ) {
                    $plugins = array( $entry['plugin'] ); // v1.8.0 migration
                }
                if ( is_multisite() || ! self::valid_plugin_selection( $plugins ) ) { continue; }
            } else { $plugins = array(); }
            $valid[ $scope ] = array( 'expires_at' => $end, 'plugins' => $plugins,
                'plugin' => isset( $plugins[0] ) ? $plugins[0] : '',
                'actor' => isset( $entry['actor'] ) ? absint( $entry['actor'] ) : 0 );
        }
        return $valid ? array( 'access_id' => (int) $record->id, 'grants' => $valid ) : null;
    }

    public static function active_scopes( $user_id, $now = null ) {
        $result = self::grant_for_user( $user_id, $now );
        return $result ? $result['grants'] : array();
    }
    public static function allowed_capabilities( $user_id ) {
        $caps = array();
        foreach ( self::active_scopes( $user_id ) as $scope => $grant ) {
            $caps = array_merge( $caps, self::scopes()[ $scope ]['caps'] );
        }
        return array_values( array_unique( $caps ) );
    }
    public static function may( $user_id, $cap ) {
        return in_array( $cap, self::allowed_capabilities( $user_id ), true );
    }
    public static function plugins_for_user( $user_id ) {
        $grants = self::active_scopes( $user_id );
        return isset( $grants['plugin_toggle']['plugins'] ) ? $grants['plugin_toggle']['plugins'] : array();
    }
    /** Compatibility for 1.8 integrations that expect one plugin. */
    public static function plugin_for_user( $user_id ) {
        $plugins = self::plugins_for_user( $user_id );
        return $plugins ? $plugins[0] : '';
    }
    public static function valid_plugin_selection( $plugins ) {
        if ( ! is_array( $plugins ) || ! $plugins || count( $plugins ) > self::MAX_PLUGINS ) { return false; }
        $available = self::available_plugins();
        $seen = array();
        foreach ( $plugins as $plugin ) {
            if ( ! is_string( $plugin ) || ! isset( $available[ $plugin ] ) ||
                $plugin === plugin_basename( AMTA_FILE ) || isset( $seen[ $plugin ] ) ) { return false; }
            $seen[ $plugin ] = true;
        }
        return true;
    }

    /** Atomic replacement: each checked scope receives its own 1-60 minute duration. */
    public static function grant_many( $record, $requests, $actor = 0 ) {
        $now = time();
        if ( ! $record || 'active' !== $record->status || (int) $record->expires_at <= $now || ! is_array( $requests ) || count( $requests ) > count( self::scopes() ) ) { return false; }
        $user_id = (int) $record->user_id;
        if ( ! AMTA_Hardening::is_temporary( $user_id ) ||
            (int) get_user_meta( $user_id, 'amta_access_id', true ) !== (int) $record->id ) { return false; }
        if ( ! $requests ) { return self::revoke( $record, $actor ); }
        $grants = array();
        foreach ( $requests as $scope => $config ) {
            if ( ! is_string( $scope ) || ! isset( self::scopes()[ $scope ] ) || ! is_array( $config ) || ! isset( $config['minutes'] ) ) { return false; }
            $raw_minutes = $config['minutes'];
            if ( ! is_numeric( $raw_minutes ) || (string) (int) $raw_minutes !== (string) $raw_minutes ) { return false; }
            $minutes = (int) $raw_minutes;
            if ( $minutes < 1 || $minutes > self::MAX_MINUTES ) { return false; }
            $end = min( $now + $minutes * MINUTE_IN_SECONDS, (int) $record->expires_at );
            if ( $end <= $now ) { return false; }
            $plugins = array();
            if ( 'plugin_toggle' === $scope ) {
                $plugins = isset( $config['plugins'] ) && is_array( $config['plugins'] ) ? $config['plugins'] : array();
                if ( ! $plugins && isset( $config['plugin'] ) && is_string( $config['plugin'] ) && $config['plugin'] ) {
                    $plugins = array( $config['plugin'] );
                }
                if ( is_multisite() || ! self::valid_plugin_selection( $plugins ) ) { return false; }
            }
            $grants[ $scope ] = array( 'expires_at' => $end, 'plugins' => $plugins,
                'plugin' => $plugins ? $plugins[0] : '', 'actor' => absint( $actor ) );
        }
        $saved = update_user_meta( $user_id, self::META_KEY, array( 'access_id' => (int) $record->id, 'grants' => $grants ) );
        if ( false === $saved && get_user_meta( $user_id, self::META_KEY, true ) !== array( 'access_id' => (int) $record->id, 'grants' => $grants ) ) { return false; }
        // Saving a custom policy makes all unchecked core-content scopes genuinely locked.
        $u = get_userdata( $user_id );
        if ( $u && in_array( AMTA_Hardening::ROLE, (array) $u->roles, true ) ) {
            update_user_meta( $user_id, self::POLICY_KEY, array( 'access_id' => (int) $record->id, 'enabled' => 1 ) );
        }
        AMTA_Storage::log( (int) $record->id, 'permission_granted', absint( $actor ) );
        return true;
    }
    /** Compatibility with v1.7 integration clients: save one permission. */
    public static function grant( $record, $scope, $minutes, $plugin = '', $actor = 0 ) {
        return self::grant_many( $record, array( $scope => array( 'minutes' => $minutes, 'plugin' => $plugin ) ), $actor );
    }
    public static function revoke( $record, $actor = 0 ) {
        if ( ! $record ) { return false; }
        delete_user_meta( (int) $record->user_id, self::META_KEY );
        AMTA_Storage::log( (int) $record->id, 'permission_locked', absint( $actor ) );
        return true;
    }
    public static function revoke_scope( $record, $scope, $actor = 0 ) {
        if ( ! $record || ! is_string( $scope ) || ! isset( self::scopes()[ $scope ] ) ||
            (int) get_user_meta( (int) $record->user_id, 'amta_access_id', true ) !== (int) $record->id ) { return false; }
        $active = self::active_scopes( (int) $record->user_id );
        if ( ! isset( $active[ $scope ] ) ) { return false; }
        unset( $active[ $scope ] );
        $result = $active ? update_user_meta( (int) $record->user_id, self::META_KEY,
            array( 'access_id' => (int) $record->id, 'grants' => $active ) ) : delete_user_meta( (int) $record->user_id, self::META_KEY );
        if ( false === $result ) { return false; }
        AMTA_Storage::log( (int) $record->id, 'permission_locked', absint( $actor ) );
        return true;
    }

    /** Limit to already installed plugin files, excluding OneClicky itself. */
    public static function available_plugins() {
        if ( is_multisite() ) { return array(); }
        if ( ! function_exists( 'get_plugins' ) ) { require_once ABSPATH . 'wp-admin/includes/plugin.php'; }
        $plugins = get_plugins();
        unset( $plugins[ plugin_basename( AMTA_FILE ) ] );
        return $plugins;
    }
    public static function approved_plugin_change( $user_id, $new, $old ) {
        if ( ! is_array( $new ) || ! is_array( $old ) || is_multisite() ) { return false; }
        $plugins = self::plugins_for_user( $user_id );
        if ( ! self::valid_plugin_selection( $plugins ) ) { return false; }
        $before = array_values( array_unique( $old ) );
        $after = array_values( array_unique( $new ) );
        $removed = array_values( array_diff( $before, $after ) );
        $added = array_values( array_diff( $after, $before ) );
        return count( $before ) === count( $old ) && count( $after ) === count( $new ) &&
            count( $removed ) + count( $added ) === 1 &&
            ( ( count( $removed ) === 1 && in_array( $removed[0], $plugins, true ) ) || ( count( $added ) === 1 && in_array( $added[0], $plugins, true ) ) );
    }
}
