<?php
/** Optional per-invitation capability DENY policy. Native WordPress roles stay intact. */
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class AMTA_Access_Locks {
    const META_KEY = 'amta_feature_locks_v112';
    private static $request_cache = array();

    public static function init() {
        add_filter( 'user_has_cap', array( __CLASS__, 'deny_selected_caps' ), 9999, 4 );
    }

    /** Groups map to actual WordPress capabilities, not cosmetic navigation changes. */
    public static function groups() {
        return array(
            'posts_edit' => array( 'title' => __( 'Posts — edit and read private', 'oneclicky-temporary-access' ), 'caps' => array( 'edit_posts', 'edit_others_posts', 'edit_published_posts', 'edit_private_posts', 'read_private_posts' ) ),
            'posts_publish' => array( 'title' => __( 'Posts — publish', 'oneclicky-temporary-access' ), 'caps' => array( 'publish_posts' ) ),
            'posts_delete' => array( 'title' => __( 'Posts — delete', 'oneclicky-temporary-access' ), 'caps' => array( 'delete_posts', 'delete_others_posts', 'delete_published_posts', 'delete_private_posts' ) ),
            'pages_edit' => array( 'title' => __( 'Pages — edit and read private', 'oneclicky-temporary-access' ), 'caps' => array( 'edit_pages', 'edit_others_pages', 'edit_published_pages', 'edit_private_pages', 'read_private_pages' ) ),
            'pages_publish' => array( 'title' => __( 'Pages — publish', 'oneclicky-temporary-access' ), 'caps' => array( 'publish_pages' ) ),
            'pages_delete' => array( 'title' => __( 'Pages — delete', 'oneclicky-temporary-access' ), 'caps' => array( 'delete_pages', 'delete_others_pages', 'delete_published_pages', 'delete_private_pages' ) ),
            'media' => array( 'title' => __( 'Media — upload files', 'oneclicky-temporary-access' ), 'caps' => array( 'upload_files' ) ),
            'comments' => array( 'title' => __( 'Comments — moderate', 'oneclicky-temporary-access' ), 'caps' => array( 'moderate_comments' ) ),
            'taxonomies' => array( 'title' => __( 'Categories and taxonomies', 'oneclicky-temporary-access' ), 'caps' => array( 'manage_categories' ) ),
            'plugins' => array( 'title' => __( 'Plugins — install, activate, edit, update, delete', 'oneclicky-temporary-access' ), 'caps' => array( 'activate_plugins', 'deactivate_plugins', 'install_plugins', 'upload_plugins', 'update_plugins', 'delete_plugins', 'edit_plugins' ) ),
            'appearance' => array( 'title' => __( 'Appearance — themes, menus, Customizer', 'oneclicky-temporary-access' ), 'caps' => array( 'edit_theme_options', 'customize', 'switch_themes', 'install_themes', 'upload_themes', 'update_themes', 'delete_themes', 'edit_themes' ) ),
            'users' => array( 'title' => __( 'Users — list, create, edit, delete and roles', 'oneclicky-temporary-access' ), 'caps' => array( 'list_users', 'create_users', 'edit_users', 'delete_users', 'remove_users', 'promote_users', 'add_users' ) ),
            'settings' => array( 'title' => __( 'Settings — site configuration', 'oneclicky-temporary-access' ), 'caps' => array( 'manage_options', 'manage_privacy_options' ) ),
            'tools' => array( 'title' => __( 'Tools — import and export', 'oneclicky-temporary-access' ), 'caps' => array( 'import', 'export' ) ),
            'core_updates' => array( 'title' => __( 'WordPress core updates', 'oneclicky-temporary-access' ), 'caps' => array( 'update_core' ) ),
            'privacy' => array( 'title' => __( 'Personal-data export and erasure', 'oneclicky-temporary-access' ), 'caps' => array( 'export_others_personal_data', 'erase_others_personal_data' ) ),
            'advanced_files' => array( 'title' => __( 'Unfiltered HTML and uploads', 'oneclicky-temporary-access' ), 'caps' => array( 'unfiltered_html', 'unfiltered_upload' ) ),
        );
    }

    /** Other capabilities registered on the Administrator role (e.g. by WooCommerce). */
    public static function advanced_caps() {
        $role = get_role( 'administrator' );
        if ( ! $role || ! isset( $role->capabilities ) || ! is_array( $role->capabilities ) ) { return array(); }
        $covered = array( 'read', 'exist', 'do_not_allow', 'manage_network', 'manage_network_options', 'manage_network_plugins', 'manage_network_themes', 'manage_network_users', 'manage_network_sites' );
        foreach ( self::groups() as $group ) { $covered = array_merge( $covered, $group['caps'] ); }
        $result = array();
        foreach ( $role->capabilities as $cap => $enabled ) {
            if ( ! $enabled || ! is_string( $cap ) || ! preg_match( '/^[a-z0-9_\-]{2,90}$/', $cap ) || in_array( $cap, $covered, true ) || preg_match( '/^level_[0-9]+$/', $cap ) || 0 === strpos( $cap, 'amta_' ) ) { continue; }
            $result[] = $cap;
        }
        sort( $result, SORT_STRING );
        return array_slice( $result, 0, 250 );
    }

    public static function read( $user_id, $access_id ) {
        $data = get_user_meta( (int) $user_id, self::META_KEY, true );
        if ( ! is_array( $data ) || ! isset( $data['access_id'] ) || (int) $data['access_id'] !== (int) $access_id ||
             (int) get_user_meta( (int) $user_id, 'amta_access_id', true ) !== (int) $access_id ) {
            return array( 'groups' => array(), 'extra_caps' => array() );
        }
        return array(
            'groups' => isset( $data['groups'] ) && is_array( $data['groups'] ) ? array_values( $data['groups'] ) : array(),
            'extra_caps' => isset( $data['extra_caps'] ) && is_array( $data['extra_caps'] ) ? array_values( $data['extra_caps'] ) : array(),
        );
    }

    public static function save( $record, $groups, $extra_caps, $actor_id ) {
        if ( ! $record || ! AMTA_Storage::is_live( $record ) || ! AMTA_Hardening::is_temporary( (int) $record->user_id ) ||
             (int) get_user_meta( (int) $record->user_id, 'amta_access_id', true ) !== (int) $record->id ||
             ! is_array( $groups ) || ! is_array( $extra_caps ) || count( $groups ) > count( self::groups() ) || count( $extra_caps ) > 250 ) {
            return false;
        }
        foreach ( $groups as $group ) { if ( ! is_string( $group ) || ! array_key_exists( $group, self::groups() ) ) { return false; } }
        $valid_caps = self::advanced_caps();
        foreach ( $extra_caps as $cap ) { if ( ! is_string( $cap ) || ! in_array( $cap, $valid_caps, true ) ) { return false; } }
        $groups = array_values( array_unique( $groups ) );
        $extra_caps = array_values( array_unique( $extra_caps ) );
        if ( ! $groups && ! $extra_caps ) {
            delete_user_meta( (int) $record->user_id, self::META_KEY );
        } else {
            update_user_meta( (int) $record->user_id, self::META_KEY, array( 'access_id' => (int) $record->id, 'groups' => $groups, 'extra_caps' => $extra_caps, 'updated_by' => absint( $actor_id ), 'updated_at' => time() ) );
        }
        unset( self::$request_cache[ (int) $record->user_id ] );
        AMTA_Storage::log( (int) $record->id, 'locks_updated', $actor_id );
        return true;
    }

    /** All DENY decisions are server-side and confined to the matching invited user. */
    public static function deny_selected_caps( $allcaps, $caps, $args, $user ) {
        if ( ! is_array( $allcaps ) || ! is_object( $user ) || empty( $user->ID ) ) { return $allcaps; }
        $uid = (int) $user->ID;
        $aid = (int) get_user_meta( $uid, 'amta_access_id', true );
        if ( ! $aid ) { return $allcaps; }
        if ( ! array_key_exists( $uid, self::$request_cache ) ) {
            $policy = self::read( $uid, $aid );
            $denied = array();
            if ( $policy['groups'] || $policy['extra_caps'] ) {
                // One database read per temporary account/request, not per capability check.
                $record = AMTA_Storage::get_for_user( $uid, $aid );
                if ( AMTA_Storage::is_live( $record ) ) {
                    $denied = $policy['extra_caps'];
                    $all_groups = self::groups();
                    foreach ( $policy['groups'] as $group ) {
                        if ( isset( $all_groups[ $group ] ) ) { $denied = array_merge( $denied, $all_groups[ $group ]['caps'] ); }
                    }
                }
            }
            self::$request_cache[ $uid ] = array_values( array_unique( $denied ) );
        }
        $denied = self::$request_cache[ $uid ];
        foreach ( array_unique( $denied ) as $cap ) { $allcaps[ $cap ] = false; }
        return $allcaps;
    }
}
