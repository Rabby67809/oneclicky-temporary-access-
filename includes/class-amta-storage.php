<?php
/** Persistence, lifecycle, and a deliberately minimal activity trail. */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class AMTA_Storage {
    public static function table() {
        global $wpdb;
        return $wpdb->prefix . 'amta_links';
    }

    public static function log_table() {
        global $wpdb;
        return $wpdb->prefix . 'amta_events';
    }

    public static function tombstone_table() {
        global $wpdb;
        return $wpdb->prefix . 'amta_removed';
    }

    /** WordPress updates do not necessarily run plugin activation hooks. */
    public static function maybe_upgrade() {
        if ( get_option( 'amta_db_version' ) !== AMTA_VERSION ) {
            self::install();
        }
    }

    public static function install( $network_wide = false ) {
        if ( is_multisite() && $network_wide ) {
            wp_die( esc_html__( 'OneClicky must be activated separately on each site, not network-wide.', 'oneclicky-temporary-access' ) );
        }
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();
        $links   = self::table();
        $events  = self::log_table();
        $removed = self::tombstone_table();
        $sql_links = "CREATE TABLE {$links} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            user_id bigint(20) unsigned NOT NULL,
            created_by bigint(20) unsigned NOT NULL,
            label varchar(100) NOT NULL,
            role varchar(100) NOT NULL,
            token_hash char(64) NOT NULL,
            secret_enc longtext NULL,
            max_uses smallint(5) unsigned NOT NULL DEFAULT 1,
            uses smallint(5) unsigned NOT NULL DEFAULT 0,
            expires_at bigint(20) unsigned NOT NULL,
            created_at bigint(20) unsigned NOT NULL,
            last_used_at bigint(20) unsigned NOT NULL DEFAULT 0,
            dashboard_entered_at bigint(20) unsigned NOT NULL DEFAULT 0,
            last_seen_at bigint(20) unsigned NOT NULL DEFAULT 0,
            closed_at bigint(20) unsigned NOT NULL DEFAULT 0,
            status varchar(16) NOT NULL DEFAULT 'active',
            PRIMARY KEY  (id),
            UNIQUE KEY token_hash (token_hash),
            KEY user_id (user_id),
            KEY status_expires (status,expires_at)
        ) {$charset};";
        $sql_events = "CREATE TABLE {$events} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            access_id bigint(20) unsigned NOT NULL,
            actor_id bigint(20) unsigned NOT NULL DEFAULT 0,
            event varchar(32) NOT NULL,
            details text NULL,
            created_at bigint(20) unsigned NOT NULL,
            PRIMARY KEY  (id),
            KEY access_id (access_id),
            KEY created_at (created_at)
        ) {$charset};";
        // Removed invitations are not retained in All Links. Only an HMAC
        // digest is kept temporarily so old links can show "Deleted" safely.
        $sql_removed = "CREATE TABLE {$removed} (
            access_id bigint(20) unsigned NOT NULL,
            token_hash char(64) NOT NULL,
            removed_at bigint(20) unsigned NOT NULL,
            PRIMARY KEY  (access_id),
            KEY removed_at (removed_at)
        ) {$charset};";
        dbDelta( $sql_links );
        dbDelta( $sql_events );
        dbDelta( $sql_removed );
        // v1.2 marked deleted links but continued displaying the rows.
        // Migrate those to sparse tombstones, then remove the full records.
        self::migrate_soft_deletes();
        update_option( 'amta_db_version', AMTA_VERSION, false );
        if ( ! wp_next_scheduled( 'amta_cleanup' ) ) {
            wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', 'amta_cleanup' );
        }
    }

    public static function deactivate() {
        // Never leave privileged temporary accounts usable after deactivation.
        self::revoke_all();
        wp_clear_scheduled_hook( 'amta_cleanup' );
    }

    public static function log( $id, $event, $actor = 0, $details = array() ) {
        global $wpdb;
        $allowed = array( 'created', 'redeemed', 'dashboard', 'revoked', 'restored', 'expired', 'deleted', 'extended', 'permission_granted', 'permission_locked', 'locks_updated', 'content_changed', 'content_deleted', 'plugin_enabled', 'plugin_disabled', 'role_changed', 'user_created', 'theme_switched', 'site_setting', 'emergency_on', 'emergency_off' );
        if ( ! in_array( $event, $allowed, true ) ) {
            return;
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
        $wpdb->insert(
            self::log_table(),
            array( 'access_id' => absint( $id ), 'actor_id' => absint( $actor ), 'event' => $event, 'details' => is_array( $details ) ? substr( wp_json_encode( $details ), 0, 750 ) : '', 'created_at' => time() ),
            array( '%d', '%d', '%s', '%s', '%d' )
        );
    }

    public static function create( $user_id, $creator_id, $label, $role, $token_hash, $max_uses, $expiry ) {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
        $success = $wpdb->insert(
            self::table(),
            array(
                'user_id' => absint( $user_id ),
                'created_by' => absint( $creator_id ),
                'label' => $label,
                'role' => $role,
                'token_hash' => $token_hash,
                'max_uses' => absint( $max_uses ),
                'uses' => 0,
                'expires_at' => absint( $expiry ),
                'created_at' => time(),
                'status' => 'active',
            ),
            array( '%d', '%d', '%s', '%s', '%s', '%d', '%d', '%d', '%d', '%s' )
        );
        if ( false === $success ) {
            return 0;
        }
        $id = absint( $wpdb->insert_id );
        self::log( $id, 'created', $creator_id );
        return $id;
    }

    public static function get( $id ) {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Access state and logs are read from custom plugin tables; revocations must not be masked by stale object-cache values.
        return $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE id = %d LIMIT 1', self::table(), absint( $id ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh access state or atomic lifecycle mutation in plugin-owned tables.
    }

    public static function get_for_user( $user_id, $access_id ) {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Access state and logs are read from custom plugin tables; revocations must not be masked by stale object-cache values.
        return $wpdb->get_row(
            $wpdb->prepare(
                'SELECT * FROM %i WHERE id = %d AND user_id = %d LIMIT 1',
                self::table(),
                absint( $access_id ),
                absint( $user_id )
            )
        ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
    }

    public static function is_live( $record ) {
        return $record && ! get_option( 'amta_emergency_lockdown', false ) && 'active' === $record->status && (int) $record->expires_at > time();
    }

    /** Consume a link use atomically, so parallel requests cannot bypass the limit. */
    public static function redeem( $record, $digest ) {
        global $wpdb;
        if ( ! self::is_live( $record ) ) {
            return false;
        }
        $now = time();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
        $affected = $wpdb->query(
            $wpdb->prepare(
                "UPDATE %i SET uses = uses + 1, last_used_at = %d WHERE id = %d AND token_hash = %s AND status = 'active' AND expires_at > %d AND uses < max_uses",
                self::table(),
                $now,
                (int) $record->id,
                $digest,
                $now
            )
        ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        if ( 1 !== $affected ) {
            return false;
        }
        // A used-up invitation must not retain a recoverable secret.
        if ( (int) $record->uses + 1 >= (int) $record->max_uses ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
            $wpdb->update( self::table(), array( 'secret_enc' => null ), array( 'id' => (int) $record->id ), array( '%s' ), array( '%d' ) );
        }
        self::log( $record->id, 'redeemed', $record->user_id );
        return true;
    }

    /** First successful WordPress Dashboard load (never just clicking a link). */
    public static function mark_dashboard_entered( $access_id, $user_id ) {
        global $wpdb;
        $now = time();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
        $updated = $wpdb->query( $wpdb->prepare(
            "UPDATE %i SET dashboard_entered_at = %d, last_seen_at = %d WHERE id = %d AND user_id = %d AND status = 'active' AND expires_at > %d AND dashboard_entered_at = 0",
            self::table(),
            $now, $now, absint( $access_id ), absint( $user_id ), $now
        ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        if ( 1 === $updated ) {
            self::log( $access_id, 'dashboard', $user_id );
        }
        return 1 === $updated;
    }

    /** Lightweight authenticated presence: only valid accounts, at most once/30s. */
    public static function ping_presence( $access_id, $user_id ) {
        global $wpdb;
        $now = time();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
        $result = $wpdb->query( $wpdb->prepare(
            "UPDATE %i SET last_seen_at = %d WHERE id = %d AND user_id = %d AND status = 'active' AND expires_at > %d AND dashboard_entered_at > 0 AND last_seen_at <= %d",
            self::table(),
            $now, absint( $access_id ), absint( $user_id ), $now, $now - 30
        ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        return false !== $result;
    }

    /** Closing a link also terminates every session of its dedicated account. */
    public static function close( $id, $reason = 'revoked', $actor = 0 ) {
        global $wpdb;
        if ( ! in_array( $reason, array( 'revoked', 'expired' ), true ) ) {
            return false;
        }
        $record = self::get( $id );
        if ( ! $record || 'active' !== $record->status ) {
            return false;
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic invitation-state update in a plugin-owned table, not safely cacheable.
        $affected = $wpdb->update(
            self::table(),
            array( 'status' => $reason, 'closed_at' => time(), 'secret_enc' => null ),
            array( 'id' => (int) $id, 'status' => 'active' ),
            array( '%s', '%d', '%s' ),
            array( '%d', '%s' )
        );
        if ( 1 !== $affected ) {
            return false;
        }
        delete_user_meta( (int) $record->user_id, AMTA_Unlock::META_KEY );
        AMTA_OTP::clear( $id );
        AMTA_Security::disable_account( $record );
        self::log( $id, $reason, $actor );
        return true;
    }

    /** The invitation itself is removed; only a non-reversible token digest
     * remains temporarily for an accessible "Deleted" status page.
     * Dedicated users are disabled, never implicitly reassigned/deleted,
     * because their existing authored posts may need preservation.
     */
    public static function delete_invitation( $id, $actor = 0 ) {
        global $wpdb;
        $record = self::get( $id );
        if ( ! $record ) {
            return false;
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
        $wpdb->query( 'START TRANSACTION' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh access state or atomic lifecycle mutation in plugin-owned tables.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
        $tombstone = $wpdb->replace(
            self::tombstone_table(),
            array( 'access_id' => (int) $record->id, 'token_hash' => $record->token_hash, 'removed_at' => time() ),
            array( '%d', '%s', '%d' )
        );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
        $deleted = false !== $tombstone && 1 === $wpdb->delete(
            self::table(),
            array( 'id' => (int) $record->id, 'token_hash' => $record->token_hash ),
            array( '%d', '%s' )
        );
        if ( ! $deleted ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
            $wpdb->query( 'ROLLBACK' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh access state or atomic lifecycle mutation in plugin-owned tables.
            return false;
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
        $wpdb->query( 'COMMIT' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh access state or atomic lifecycle mutation in plugin-owned tables.
        // The record is gone before sessions are destroyed; concurrent
        // requests already fail their per-request database authorization.
        delete_user_meta( (int) $record->user_id, AMTA_Unlock::META_KEY );
        AMTA_OTP::clear( $id );
        AMTA_Security::disable_account( $record );
        delete_user_meta( (int) $record->user_id, 'amta_recipient_email' );
        self::log( $id, 'deleted', $actor );
        return true;
    }

    /** Migrate legacy v1.2 soft-deleted rows without exposing them in listings. */
    private static function migrate_soft_deletes() {
        global $wpdb;
        for ( $batch = 0; $batch < 40; $batch++ ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Access state and logs are read from custom plugin tables; revocations must not be masked by stale object-cache values.
            $rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, token_hash FROM %i WHERE status = 'deleted' ORDER BY id ASC LIMIT 100", self::table() ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh access state or atomic lifecycle mutation in plugin-owned tables.
            if ( ! $rows ) {
                break;
            }
            foreach ( $rows as $row ) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
                $result = $wpdb->replace( self::tombstone_table(), array(
                    'access_id' => (int) $row->id,
                    'token_hash' => $row->token_hash,
                    'removed_at' => time(),
                ), array( '%d', '%s', '%d' ) );
                if ( false === $result ) {
                    return;
                }
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
                $wpdb->delete( self::table(), array( 'id' => (int) $row->id, 'status' => 'deleted' ), array( '%d', '%s' ) );
            }
            if ( count( $rows ) < 100 ) {
                break;
            }
        }
    }

    public static function is_deleted_token( $id, $digest ) {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Access state and logs are read from custom plugin tables; revocations must not be masked by stale object-cache values.
        $stored = $wpdb->get_var( $wpdb->prepare(
            'SELECT token_hash FROM %i WHERE access_id = %d LIMIT 1', self::tombstone_table(), absint( $id )
        ) );
        return is_string( $stored ) && hash_equals( $stored, $digest );
    }

    /** Re-issue a brand new one-time token within 120 seconds of revocation.
     * Old URLs stay invalid; old user sessions remain destroyed.
     */
    public static function restore( $id, $expires_at, $token_hash, $actor = 0 ) {
        global $wpdb;
        $now = time();
        $record = self::get( $id );
        if ( ! $record || 'revoked' !== $record->status ||
            (int) $record->closed_at <= 0 ||
            (int) $record->closed_at + 120 < $now ||
            (int) $record->closed_at > $now ||
            $expires_at < $now + 300 || $expires_at > $now + 365 * DAY_IN_SECONDS ||
            ! preg_match( '/\A[a-f0-9]{64}\z/D', $token_hash ) ) {
            return false;
        }
        if ( ! isset( get_editable_roles()[ $record->role ] ) ||
            (int) get_user_meta( (int) $record->user_id, 'amta_access_id', true ) !== (int) $id ||
            ! get_userdata( (int) $record->user_id ) ) {
            return false;
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic invitation-state update in a plugin-owned table, not safely cacheable.
        $affected = $wpdb->update(
            self::table(),
            array( 'status' => 'active', 'closed_at' => 0, 'expires_at' => absint( $expires_at ), 'uses' => 0, 'last_used_at' => 0, 'dashboard_entered_at' => 0, 'last_seen_at' => 0, 'token_hash' => $token_hash, 'secret_enc' => null ),
            array( 'id' => (int) $id, 'status' => 'revoked', 'closed_at' => (int) $record->closed_at ),
            array( '%s', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%s', '%s' ),
            array( '%d', '%s', '%d' )
        );
        if ( 1 !== $affected ) {
            return false;
        }
        AMTA_OTP::clear( $id );
        $user = get_userdata( (int) $record->user_id );
        if ( ! $user ) {
            self::close( $id, 'revoked', $actor );
            return false;
        }
        $user->set_role( AMTA_Hardening::safe_role( $record->role ) );
        self::log( $id, 'restored', $actor );
        return true;
    }

    /** Edit only currently active links, never revive expired or closed links. */
    public static function update_expiration( $id, $expires_at, $actor = 0 ) {
        global $wpdb;
        $record = self::get( $id );
        $now = time();
        if ( ! self::is_live( $record ) || $expires_at < $now + 300 || $expires_at > $now + 365 * DAY_IN_SECONDS ) {
            return false;
        }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic invitation-state update in a plugin-owned table, not safely cacheable.
        $affected = $wpdb->update(
            self::table(),
            array( 'expires_at' => absint( $expires_at ) ),
            array( 'id' => (int) $id, 'status' => 'active', 'expires_at' => (int) $record->expires_at ),
            array( '%d' ),
            array( '%d', '%s', '%d' )
        );
        if ( 1 !== $affected ) {
            return false;
        }
        self::log( $id, 'extended', $actor );
        return true;
    }

    public static function revoke_all() {
        global $wpdb;
        // This loop is bounded per database query for memory safety.
        do {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Access state and logs are read from custom plugin tables; revocations must not be masked by stale object-cache values.
            $ids = $wpdb->get_col( $wpdb->prepare( "SELECT id FROM %i WHERE status = 'active' ORDER BY id ASC LIMIT 100", self::table() ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh access state or atomic lifecycle mutation in plugin-owned tables.
            $closed = 0;
            foreach ( $ids as $id ) {
                if ( self::close( (int) $id, 'revoked' ) ) {
                    $closed++;
                }
            }
            if ( 0 === $closed ) {
                break; // Avoid looping forever if the database cannot be updated.
            }
        } while ( count( $ids ) === 100 );
    }

    public static function cleanup() {
        global $wpdb;
        $now = time();
        // Expire all due rows; cap individual batch sizes to avoid high memory usage.
        for ( $i = 0; $i < 30; $i++ ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Access state and logs are read from custom plugin tables; revocations must not be masked by stale object-cache values.
            $ids = $wpdb->get_col(
                $wpdb->prepare(
                    "SELECT id FROM %i WHERE status = 'active' AND expires_at <= %d ORDER BY id ASC LIMIT 100",
                    self::table(),
                    $now
                )
            ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            foreach ( $ids as $id ) {
                self::close( (int) $id, 'expired' );
            }
            if ( count( $ids ) < 100 ) {
                break;
            }
        }
        // Remove any leftover soft-deleted v1.2 rows in bounded batches.
        self::migrate_soft_deletes();
        // A revoked link is never auto-restored; the 2-minute window is
        // enforced server-side on every restore request.
        // Keep a sparse deleted-token tombstone for 90 days only.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
        $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE removed_at < %d', self::tombstone_table(), $now - 90 * DAY_IN_SECONDS ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh access state or atomic lifecycle mutation in plugin-owned tables.
        // Privacy-friendly minimal event retention: 90 days.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
        $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE created_at < %d', self::log_table(), $now - 90 * DAY_IN_SECONDS ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh access state or atomic lifecycle mutation in plugin-owned tables.
    }

    public static function counts() {
        global $wpdb;
        $now = time();
        return array(
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Access state and logs are read from custom plugin tables; revocations must not be masked by stale object-cache values.
            'active'  => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE status = 'active' AND expires_at > %d", self::table(), $now ) ),
            'expired' => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE status = 'expired' OR (status = 'active' AND expires_at <= %d)", self::table(), $now ) ),
            'revoked' => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE status = 'revoked'", self::table() ) ), // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        );
    }

    public static function total() {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Access state and logs are read from custom plugin tables; revocations must not be masked by stale object-cache values.
        return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE status <> 'deleted'", self::table() ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh access state or atomic lifecycle mutation in plugin-owned tables.
    }

    /**
     * Normalize listing filters before sending each value as a separate,
     * explicitly bound argument to wpdb::prepare().
     */
    private static function listing_filters( $status, $search ) {
        global $wpdb;
        $status = in_array( $status, array( 'all', 'active', 'expired', 'revoked' ), true ) ? $status : 'all';
        $search = is_string( $search ) ? $search : '';
        $now    = time();
        $like   = '%' . $wpdb->esc_like( $search ) . '%';
        return array( $status, $search, $now, $like );
    }

    /** Return an accurate, uncached count for the requested filter. */
    public static function filtered_total( $status = 'all', $search = '' ) {
        global $wpdb;
        list( $status, $search, $now, $like ) = self::listing_filters( $status, $search );
        // OneClicky owns these tables; fresh queries are needed to reflect revocation immediately.
        return (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom-table access state must not be served from a stale object cache.
            $wpdb->prepare(
                "SELECT COUNT(*) FROM %i l LEFT JOIN %i e ON (e.user_id = l.user_id AND e.meta_key = %s)
                WHERE l.status <> %s
                AND (
                    %s = 'all'
                    OR (%s = 'active' AND l.status = 'active' AND l.expires_at > %d)
                    OR (%s = 'expired' AND (l.status = 'expired' OR (l.status = 'active' AND l.expires_at <= %d)))
                    OR (%s = 'revoked' AND l.status = 'revoked')
                )
                AND (%s = '' OR l.label LIKE %s OR e.meta_value LIKE %s OR CAST(l.id AS CHAR) = %s)",
                self::table(),
                $wpdb->usermeta,
                'amta_recipient_email',
                'deleted',
                $status,
                $status,
                $now,
                $status,
                $now,
                $status,
                $search,
                $like,
                $like,
                $search
            )
        );
    }

    /** Return a fresh, bounded page of invitations. */
    public static function page( $limit, $offset, $status = 'all', $search = '' ) {
        global $wpdb;
        list( $status, $search, $now, $like ) = self::listing_filters( $status, $search );
        $limit  = max( 1, absint( $limit ) );
        $offset = absint( $offset );

        return $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom-table invitation status must be immediately fresh.
            $wpdb->prepare(
                "SELECT l.*, e.meta_value AS recipient_email FROM %i l
                LEFT JOIN %i e ON (e.user_id = l.user_id AND e.meta_key = %s)
                WHERE l.status <> %s
                AND (
                    %s = 'all'
                    OR (%s = 'active' AND l.status = 'active' AND l.expires_at > %d)
                    OR (%s = 'expired' AND (l.status = 'expired' OR (l.status = 'active' AND l.expires_at <= %d)))
                    OR (%s = 'revoked' AND l.status = 'revoked')
                )
                AND (%s = '' OR l.label LIKE %s OR e.meta_value LIKE %s OR CAST(l.id AS CHAR) = %s)
                ORDER BY l.id DESC LIMIT %d OFFSET %d",
                self::table(),
                $wpdb->usermeta,
                'amta_recipient_email',
                'deleted',
                $status,
                $status,
                $now,
                $status,
                $now,
                $status,
                $search,
                $like,
                $like,
                $search,
                $limit,
                $offset
            )
        );
    }

    public static function latest_events( $limit = 30 ) {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Access state and logs are read from custom plugin tables; revocations must not be masked by stale object-cache values.
        return $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i ORDER BY id DESC LIMIT %d', self::log_table(), absint( $limit ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh access state or atomic lifecycle mutation in plugin-owned tables.
    }
}
