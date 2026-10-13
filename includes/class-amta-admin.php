<?php
/** Dashboard UI and administrator-only actions. */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class AMTA_Admin {
    private static $new_links = array();
    private static $error = '';
    private static $info = '';

    public static function init() {
        add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
        add_action( 'admin_init', array( __CLASS__, 'handle_create' ) );
        add_action( 'admin_post_amta_revoke', array( __CLASS__, 'handle_revoke' ) );
        add_action( 'admin_init', array( __CLASS__, 'handle_restore' ), 11 );
        add_action( 'admin_post_amta_delete', array( __CLASS__, 'handle_delete' ) );
        add_action( 'admin_post_amta_update_expiry', array( __CLASS__, 'handle_update_expiry' ) );
        add_action( 'admin_post_amta_save_locks', array( __CLASS__, 'handle_save_locks' ) );
        add_action( 'admin_post_amta_emergency', array( 'AMTA_Guard', 'handle_emergency' ) );
        add_action( 'admin_post_amta_alert_settings', array( 'AMTA_Guard', 'handle_alert_settings' ) );
        add_action( 'admin_post_amta_mail_test', array( 'AMTA_Guard', 'handle_mail_test' ) );
        add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
    }

    public static function menu() {
        if ( AMTA_Hardening::is_temporary( get_current_user_id() ) ) { return; }
        add_menu_page(
            __( 'OneClicky Temporary Access', 'oneclicky-temporary-access' ),
            __( 'OneClicky', 'oneclicky-temporary-access' ),
            'manage_options',
            'oneclicky-temporary-access',
            array( __CLASS__, 'render' ),
            'dashicons-shield-alt',
            59
        );
    }

    public static function assets( $hook ) {
        if ( 'toplevel_page_oneclicky-temporary-access' !== $hook ) {
            return;
        }
        wp_enqueue_style( 'amta-admin', AMTA_URL . 'assets/css/admin.css', array(), AMTA_VERSION );
        wp_enqueue_script( 'amta-admin', AMTA_URL . 'assets/js/admin.js', array(), AMTA_VERSION, true );
        wp_localize_script(
            'amta-admin',
            'amtaUI',
            array(
                'copied' => __( 'Copied to clipboard', 'oneclicky-temporary-access' ),
                'copyFailed' => __( 'Select the link and copy it manually.', 'oneclicky-temporary-access' ),
                'confirmRevoke' => __( 'Revoke this access now? Any active session will be signed out.', 'oneclicky-temporary-access' ),
                'confirmDelete' => __( 'Permanently remove this invitation from All Links? Its access will stop immediately. A minimal token fingerprint and short audit event may be kept for status/security.', 'oneclicky-temporary-access' ),
                'confirmRestore' => __( 'Restore this access with a NEW secure link? The original link and all previous login sessions will remain invalid.', 'oneclicky-temporary-access' ),
                'presence' => array( 'url' => admin_url( 'admin-ajax.php' ), 'nonce' => wp_create_nonce( 'amta_presence_statuses' ), 'refreshMs' => 30000 ),
            )
        );
    }

    /** Handle single and bulk creation with identical access controls. */
    public static function handle_create() {
        if ( ! isset( $_POST['amta_action'], $_GET['page'] ) || 'oneclicky-temporary-access' !== sanitize_key( wp_unslash( $_GET['page'] ) ) ) {
            return;
        }
        $action = is_string( $_POST['amta_action'] ) ? sanitize_key( wp_unslash( $_POST['amta_action'] ) ) : '';
        if ( ! in_array( $action, array( 'create', 'create_bulk' ), true ) ) {
            return;
        }
        if ( AMTA_Hardening::is_temporary( get_current_user_id() ) || ! current_user_can( 'manage_options' ) || ! current_user_can( 'create_users' ) || ! current_user_can( 'promote_users' ) ) {
            wp_die( esc_html__( 'You do not have permission to create temporary users.', 'oneclicky-temporary-access' ), '', array( 'response' => 403 ) );
        }
        check_admin_referer( 'amta_create', 'amta_nonce' );
        $role = isset( $_POST['amta_role'] ) && is_string( $_POST['amta_role'] ) ? sanitize_key( wp_unslash( $_POST['amta_role'] ) ) : '';
        $expires_at = self::resolve_expiration( $_POST );
        $max_uses = isset( $_POST['amta_max_uses'] ) ? absint( $_POST['amta_max_uses'] ) : 0;
        $send_email = isset( $_POST['amta_send_email'] ) && '1' === $_POST['amta_send_email'];
        $require_otp = isset( $_POST['amta_require_otp'] ) && '1' === $_POST['amta_require_otp'];
        if ( AMTA_Guard::locked() ) {
            self::$error = __( 'Emergency Lock is enabled. Unlock security mode before creating invitations.', 'oneclicky-temporary-access' );
            return;
        }
        if ( ! array_key_exists( $role, get_editable_roles() ) ) {
            self::$error = __( 'Choose an available WordPress role.', 'oneclicky-temporary-access' );
            return;
        }
        if ( is_wp_error( $expires_at ) ) {
            self::$error = $expires_at->get_error_message();
            return;
        }
        if ( ! in_array( $max_uses, array( 1, 3, 5, 10 ), true ) ) {
            self::$error = __( 'Choose a valid duration and invitation use limit.', 'oneclicky-temporary-access' );
            return;
        }
        if ( 'administrator' === $role ) {
            if ( ! isset( $_POST['amta_confirm_admin'] ) || '1' !== $_POST['amta_confirm_admin'] ) {
                self::$error = __( 'Confirm that you understand temporary Administrator access has the full WordPress Administrator capabilities.', 'oneclicky-temporary-access' );
                return;
            }
            if ( is_multisite() && ! is_super_admin() ) {
                self::$error = __( 'Only a Network Super Admin can authorize temporary Administrator access on Multisite.', 'oneclicky-temporary-access' );
                return;
            }
        }

        if ( 'create_bulk' === $action ) {
            $raw = isset( $_POST['amta_bulk'] ) && is_string( $_POST['amta_bulk'] ) ? sanitize_textarea_field( wp_unslash( $_POST['amta_bulk'] ) ) : '';
            $recipients = AMTA_Creator::parse_bulk( $raw );
        } else {
            $name = isset( $_POST['amta_name'] ) && is_string( $_POST['amta_name'] ) ? sanitize_text_field( wp_unslash( $_POST['amta_name'] ) ) : '';
            $email = isset( $_POST['amta_email'] ) && is_string( $_POST['amta_email'] ) ? sanitize_email( wp_unslash( $_POST['amta_email'] ) ) : '';
            $recipient = AMTA_Creator::validate_recipient( $name, $email );
            $recipients = is_wp_error( $recipient ) ? $recipient : array( $recipient );
        }
        if ( is_wp_error( $recipients ) ) {
            self::$error = $recipients->get_error_message();
            return;
        }
        $failed = array();
        $mail_ok = 0;
        $mail_failed = 0;
        foreach ( $recipients as $index => $recipient ) {
            $result = AMTA_Creator::create( $recipient, $role, $expires_at, $max_uses, $require_otp );
            if ( is_wp_error( $result ) ) {
                $failed[] = sprintf( /* translators: 1: recipient row number; 2: failure reason */ __( 'Recipient %1$d: %2$s', 'oneclicky-temporary-access' ), $index + 1, $result->get_error_message() );
                continue;
            }
            self::$new_links[] = $result;
            if ( $send_email ) {
                if ( AMTA_Creator::email_invitation( $result ) ) {
                    $mail_ok++;
                } else {
                    $mail_failed++;
                }
            }
        }
        if ( $failed ) {
            self::$error = implode( ' ', $failed );
        }
        if ( self::$new_links ) {
            $count = count( self::$new_links );
            self::$info = sprintf( /* translators: %d: number of temporary access accounts */ _n( '%d separate temporary account created.', '%d separate temporary accounts created.', $count, 'oneclicky-temporary-access' ), $count );
            if ( $send_email ) {
                self::$info .= ' ' . sprintf( /* translators: 1: accepted by email service; 2: failed mail submissions */ __( 'Email sending: %1$d accepted, %2$d failed. Acceptance does not guarantee delivery.', 'oneclicky-temporary-access' ), $mail_ok, $mail_failed );
            }
        }
        // The raw invitation token is displayed only in this response.
    }

    /** Restore is POSTed to admin.php?view=links so the newly generated
     * token appears in the response without ever being persisted in options.
     */
    public static function handle_restore() {
        if ( ! isset( $_GET['page'], $_POST['amta_action'] ) ||
            'oneclicky-temporary-access' !== sanitize_key( wp_unslash( $_GET['page'] ) ) ||
            'restore' !== sanitize_key( wp_unslash( $_POST['amta_action'] ) ) ) {
            return;
        }
        if ( AMTA_Hardening::is_temporary( get_current_user_id() ) || ! current_user_can( 'manage_options' ) || ! current_user_can( 'create_users' ) || ! current_user_can( 'promote_users' ) ) {
            wp_die( esc_html__( 'Not allowed to restore temporary accounts.', 'oneclicky-temporary-access' ), '', array( 'response' => 403 ) );
        }
        $id = isset( $_POST['amta_id'] ) ? absint( wp_unslash( $_POST['amta_id'] ) ) : 0;
        check_admin_referer( 'amta_restore_' . $id, 'amta_nonce' );
        $record = AMTA_Storage::get( $id );
        if ( AMTA_Guard::locked() ) { self::$error = __( 'Emergency Lock must be switched off before restoring an invitation.', 'oneclicky-temporary-access' ); return; }
        if ( ! $record || 'revoked' !== $record->status || time() > (int) $record->closed_at + 120 ) {
            self::$error = __( 'The 2-minute restore window has ended. Create a new invitation instead.', 'oneclicky-temporary-access' );
            return;
        }
        if ( 'administrator' === $record->role && ( ! isset( $_POST['amta_confirm_admin'] ) || '1' !== $_POST['amta_confirm_admin'] || ( is_multisite() && ! is_super_admin() ) ) ) {
            self::$error = __( 'Full Administrator restoration requires confirmation and sufficient privileges.', 'oneclicky-temporary-access' );
            return;
        }
        $expiry = (int) $record->expires_at;
        if ( isset( $_POST['amta_extend_expiry'] ) && '1' === $_POST['amta_extend_expiry'] ) {
            $expiry = self::resolve_expiration( array(
                'amta_duration' => 'exact',
                'amta_exact_time' => isset( $_POST['amta_exact_time'] ) && is_string( $_POST['amta_exact_time'] ) ? sanitize_text_field( wp_unslash( $_POST['amta_exact_time'] ) ) : '',
            ) );
        }
        if ( is_wp_error( $expiry ) ) {
            self::$error = $expiry->get_error_message();
            return;
        }
        if ( $expiry < time() + 300 ) {
            self::$error = __( 'The original expiration is too close or already passed. Select a new expiry before restoring.', 'oneclicky-temporary-access' );
            return;
        }
        try {
            $token = bin2hex( random_bytes( 32 ) );
        } catch ( Exception $e ) {
            self::$error = __( 'A secure replacement link could not be generated.', 'oneclicky-temporary-access' );
            return;
        }
        if ( ! AMTA_Storage::restore( $id, (int) $expiry, AMTA_Security::digest( $token ), get_current_user_id() ) ) {
            self::$error = __( 'Restore failed or the 2-minute window has ended.', 'oneclicky-temporary-access' );
            return;
        }
        if ( ! AMTA_Vault::save( $id, $token ) ) {
            AMTA_Storage::close( $id, 'revoked', get_current_user_id() );
            self::$error = __( 'Restored invitation could not be encrypted, so it was revoked for safety. Create a new invitation.', 'oneclicky-temporary-access' );
            return;
        }
        $email = (string) get_user_meta( (int) $record->user_id, 'amta_recipient_email', true );
        self::$new_links[] = array(
            'id' => $id,
            'name' => $record->label,
            'email' => $email,
            'url' => add_query_arg( array( 'amta_access' => $id, 'amta_token' => $token ), wp_login_url() ),
        );
        self::$info = __( 'Access restored. Copy the NEW secure link now; the old link and prior sessions remain invalid.', 'oneclicky-temporary-access' );
    }

    public static function handle_revoke() {
        if ( AMTA_Hardening::is_temporary( get_current_user_id() ) || ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Not allowed.', 'oneclicky-temporary-access' ), '', array( 'response' => 403 ) );
        }
        $id = isset( $_POST['amta_id'] ) ? absint( wp_unslash( $_POST['amta_id'] ) ) : 0;
        check_admin_referer( 'amta_revoke_' . $id, 'amta_nonce' );
        $success = $id && AMTA_Storage::close( $id, 'revoked', get_current_user_id() );
        wp_safe_redirect( add_query_arg( 'amta_notice', $success ? 'revoked' : 'unchanged', admin_url( 'admin.php?page=oneclicky-temporary-access&view=links' ) ) );
        exit;
    }

    /** Interpret time controls server-side, regardless of JavaScript visibility. */
    public static function resolve_expiration( $post, $relative_anchor = null ) {
        $raw = isset( $post['amta_duration'] ) && is_scalar( $post['amta_duration'] ) ? sanitize_text_field( wp_unslash( $post['amta_duration'] ) ) : '';
        $now = time();
        $base = null === $relative_anchor ? $now : (int) $relative_anchor;
        if ( ctype_digit( $raw ) && in_array( (int) $raw, array( 15, 30, 60, 120, 360, 720, 1440, 10080, 43200 ), true ) ) {
            $timestamp = $base + (int) $raw * MINUTE_IN_SECONDS;
        } elseif ( 'custom' === $raw ) {
            $amount = isset( $post['amta_custom_value'] ) && is_scalar( $post['amta_custom_value'] ) ? trim( (string) wp_unslash( $post['amta_custom_value'] ) ) : '';
            $unit = isset( $post['amta_custom_unit'] ) && is_scalar( $post['amta_custom_unit'] ) ? sanitize_key( wp_unslash( $post['amta_custom_unit'] ) ) : '';
            $units = array( 'minutes' => MINUTE_IN_SECONDS, 'hours' => HOUR_IN_SECONDS, 'days' => DAY_IN_SECONDS );
            if ( ! ctype_digit( $amount ) || strlen( $amount ) > 7 || ! isset( $units[ $unit ] ) ) {
                return new WP_Error( 'amta_bad_custom', __( 'Enter a valid custom time and unit.', 'oneclicky-temporary-access' ) );
            }
            $timestamp = $base + (int) $amount * $units[ $unit ];
        } elseif ( 'exact' === $raw ) {
            $date = isset( $post['amta_exact_time'] ) && is_scalar( $post['amta_exact_time'] ) ? trim( (string) wp_unslash( $post['amta_exact_time'] ) ) : '';
            if ( ! preg_match( '/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}\z/D', $date ) ) {
                return new WP_Error( 'amta_bad_date', __( 'Choose a valid expiration date and time.', 'oneclicky-temporary-access' ) );
            }
            $parsed = DateTimeImmutable::createFromFormat( '!Y-m-d\TH:i', $date, wp_timezone() );
            if ( ! $parsed || $parsed->format( 'Y-m-d\TH:i' ) !== $date ) {
                return new WP_Error( 'amta_bad_date', __( 'Choose a valid expiration date and time.', 'oneclicky-temporary-access' ) );
            }
            $timestamp = $parsed->getTimestamp();
        } else {
            return new WP_Error( 'amta_bad_duration', __( 'Choose a preset, custom duration or exact expiration time.', 'oneclicky-temporary-access' ) );
        }
        if ( $timestamp < $now + 5 * MINUTE_IN_SECONDS || $timestamp > $now + 365 * DAY_IN_SECONDS ) {
            return new WP_Error( 'amta_duration_bounds', __( 'Expiration must be at least 5 minutes and at most 365 days from now.', 'oneclicky-temporary-access' ) );
        }
        return $timestamp;
    }

    public static function handle_update_expiry() {
        if ( AMTA_Hardening::is_temporary( get_current_user_id() ) || ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Not allowed.', 'oneclicky-temporary-access' ), '', array( 'response' => 403 ) );
        }
        $id = isset( $_POST['amta_id'] ) ? absint( wp_unslash( $_POST['amta_id'] ) ) : 0;
        check_admin_referer( 'amta_expiry_' . $id, 'amta_nonce' );
        // The server controls the original expiry; never trust a posted timestamp.
        $record = $id ? AMTA_Storage::get( $id ) : null;
        $mode = isset( $_POST['amta_duration'] ) && is_scalar( $_POST['amta_duration'] ) ? sanitize_text_field( wp_unslash( $_POST['amta_duration'] ) ) : 'exact';
        $basis = isset( $_POST['amta_expiry_basis'] ) && is_scalar( $_POST['amta_expiry_basis'] ) ? sanitize_key( wp_unslash( $_POST['amta_expiry_basis'] ) ) : 'now';
        $is_relative = 'custom' === $mode || ctype_digit( $mode );
        $valid_basis = in_array( $basis, array( 'now', 'current' ), true );
        $anchor = $valid_basis && $is_relative && 'current' === $basis && $record ? (int) $record->expires_at : null;
        $post = array(
            'amta_duration' => $mode,
            'amta_custom_value' => isset( $_POST['amta_custom_value'] ) && is_string( $_POST['amta_custom_value'] ) ? sanitize_text_field( wp_unslash( $_POST['amta_custom_value'] ) ) : '',
            'amta_custom_unit' => isset( $_POST['amta_custom_unit'] ) && is_string( $_POST['amta_custom_unit'] ) ? sanitize_key( wp_unslash( $_POST['amta_custom_unit'] ) ) : '',
            'amta_exact_time' => isset( $_POST['amta_exact_time'] ) && is_string( $_POST['amta_exact_time'] ) ? sanitize_text_field( wp_unslash( $_POST['amta_exact_time'] ) ) : '',
        );
        $time = ! $valid_basis || ! $record || ! AMTA_Storage::is_live( $record )
            ? new WP_Error( 'amta_invalid_expiry_request', __( 'This invitation cannot be edited.', 'oneclicky-temporary-access' ) )
            : self::resolve_expiration( $post, $anchor );
        $updated = ! is_wp_error( $time ) && $id && AMTA_Storage::update_expiration( $id, $time, get_current_user_id() );
        wp_safe_redirect( add_query_arg( 'amta_notice', $updated ? 'updated' : 'update_failed', admin_url( 'admin.php?page=oneclicky-temporary-access&view=links' ) ) . '#amta-invitation-' . $id );
        exit;
    }

    public static function handle_delete() {
        if ( AMTA_Hardening::is_temporary( get_current_user_id() ) || ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Not allowed.', 'oneclicky-temporary-access' ), '', array( 'response' => 403 ) );
        }
        $id = isset( $_POST['amta_id'] ) ? absint( wp_unslash( $_POST['amta_id'] ) ) : 0;
        check_admin_referer( 'amta_delete_' . $id, 'amta_nonce' );
        $deleted = $id && AMTA_Storage::delete_invitation( $id, get_current_user_id() );
        wp_safe_redirect( add_query_arg( 'amta_notice', $deleted ? 'deleted' : 'unchanged', admin_url( 'admin.php?page=oneclicky-temporary-access&view=links' ) ) );
        exit;
    }

    /** Grant or immediately revoke scoped unlocks. Never accessible to invited users. */
    public static function handle_permission() {
        if ( AMTA_Hardening::is_temporary( get_current_user_id() ) || ! current_user_can( 'manage_options' ) || ! current_user_can( 'create_users' ) || ! current_user_can( 'promote_users' ) ) {
            wp_die( esc_html__( 'Only the site owner may change temporary permissions.', 'oneclicky-temporary-access' ), '', array( 'response' => 403 ) );
        }
        $id = isset( $_POST['amta_id'] ) ? absint( wp_unslash( $_POST['amta_id'] ) ) : 0;
        check_admin_referer( 'amta_permission_' . $id, 'amta_nonce' );
        $record = $id ? AMTA_Storage::get( $id ) : null;
        $mode = isset( $_POST['amta_mode'] ) && is_string( $_POST['amta_mode'] ) ? sanitize_key( wp_unslash( $_POST['amta_mode'] ) ) : '';
        $ok = false;
        if ( 'lock' === $mode ) {
            $ok = $record && AMTA_Unlock::revoke( $record, get_current_user_id() );
        } elseif ( 'lock_scope' === $mode ) {
            $scope = isset( $_POST['amta_scope'] ) && is_string( $_POST['amta_scope'] ) ? sanitize_key( wp_unslash( $_POST['amta_scope'] ) ) : '';
            $ok = $record && AMTA_Unlock::revoke_scope( $record, $scope, get_current_user_id() );
        } elseif ( 'grant' === $mode ) {
            // Only known capability groups are accepted; never trust arbitrary capabilities from POST.
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Array elements are unslashed and sanitized individually; scope names are whitelisted.
            $requested = isset( $_POST['amta_scopes'] ) && is_array( $_POST['amta_scopes'] ) ? array_map( 'sanitize_key', array_filter( wp_unslash( $_POST['amta_scopes'] ), 'is_string' ) ) : array();
            $posted_minutes = isset( $_POST['amta_scope_minutes'] ) && is_array( $_POST['amta_scope_minutes'] ) ? array_map( 'absint', wp_unslash( $_POST['amta_scope_minutes'] ) ) : array();
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Array values are sanitized; chosen plugin basenames are verified later.
            $plugins = isset( $_POST['amta_plugins'] ) && is_array( $_POST['amta_plugins'] ) ? array_map( 'sanitize_text_field', array_filter( wp_unslash( $_POST['amta_plugins'] ), 'is_string' ) ) : array();
            if ( count( $plugins ) > AMTA_Unlock::MAX_PLUGINS ) { $plugins = array( '__too_many__' ); }
            $plugins = array_map( 'sanitize_text_field', array_filter( $plugins, 'is_string' ) );
            $grants = array();
            $invalid = count( $requested ) > count( AMTA_Unlock::scopes() );
            foreach ( $requested as $scope ) {
                if ( ! is_scalar( $scope ) ) { $invalid = true; break; }
                $scope = sanitize_key( (string) $scope );
                if ( ! isset( AMTA_Unlock::scopes()[ $scope ] ) || isset( $grants[ $scope ] ) ) { $invalid = true; break; }
                $minutes = isset( $posted_minutes[ $scope ] ) && is_scalar( $posted_minutes[ $scope ] ) ? (string) $posted_minutes[ $scope ] : '';
                $grants[ $scope ] = array( 'minutes' => $minutes, 'plugins' => 'plugin_toggle' === $scope ? $plugins : array() );
            }
            $ok = ! $invalid && $record && AMTA_Unlock::grant_many( $record, $grants, get_current_user_id() );
        }
        wp_safe_redirect( add_query_arg( 'amta_notice', $ok ? ( 'lock' === $mode ? 'permission_locked' : 'permission_granted' ) : 'permission_failed', admin_url( 'admin.php?page=oneclicky-temporary-access&view=links' ) ) );
        exit;
    }


    /** Owner-only per-invitation feature locks. Unchecked features retain native role access. */
    public static function handle_save_locks() {
        if ( AMTA_Hardening::is_temporary( get_current_user_id() ) || ! current_user_can( 'manage_options' ) ||
             ! current_user_can( 'create_users' ) || ! current_user_can( 'promote_users' ) ) {
            wp_die( esc_html__( 'Only a non-temporary site administrator can edit feature locks.', 'oneclicky-temporary-access' ), '', array( 'response' => 403 ) );
        }
        $id = isset( $_POST['amta_id'] ) ? absint( wp_unslash( $_POST['amta_id'] ) ) : 0;
        check_admin_referer( 'amta_feature_locks_' . $id, 'amta_nonce' );
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Array elements are individually unslashed and sanitized below, then checked against allowed capabilities.
        $groups = isset( $_POST['amta_locked_groups'] ) && is_array( $_POST['amta_locked_groups'] ) ? array_map( 'sanitize_key', array_filter( wp_unslash( $_POST['amta_locked_groups'] ), 'is_string' ) ) : array();
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Array elements are individually unslashed and sanitized below, then checked against allowed capabilities.
        $extra = isset( $_POST['amta_locked_caps'] ) && is_array( $_POST['amta_locked_caps'] ) ? array_map( 'sanitize_key', array_filter( wp_unslash( $_POST['amta_locked_caps'] ), 'is_string' ) ) : array();
        $record = $id ? AMTA_Storage::get( $id ) : null;
        $success = AMTA_Access_Locks::save( $record, $groups, $extra, get_current_user_id() );
        wp_safe_redirect( add_query_arg( 'amta_notice', $success ? 'locks_saved' : 'locks_failed', admin_url( 'admin.php?page=oneclicky-temporary-access&view=links' ) ) . '#amta-invitation-' . $id );
        exit;
    }

    private static function duration_fields( $suffix ) {
        $suffix = sanitize_key( $suffix );
        ?>
        <div class="amta-duration-fields">
            <div class="amta-field"><label for="amta-duration-<?php echo esc_attr( $suffix ); ?>"><?php esc_html_e( 'Expires after', 'oneclicky-temporary-access' ); ?></label>
                <select id="amta-duration-<?php echo esc_attr( $suffix ); ?>" name="amta_duration" class="amta-duration-select">
                    <option value="15"><?php esc_html_e( '15 minutes', 'oneclicky-temporary-access' ); ?></option>
                    <option value="60"><?php esc_html_e( '1 hour', 'oneclicky-temporary-access' ); ?></option>
                    <option value="360"><?php esc_html_e( '6 hours', 'oneclicky-temporary-access' ); ?></option>
                    <option value="1440" selected><?php esc_html_e( '1 day', 'oneclicky-temporary-access' ); ?></option>
                    <option value="10080"><?php esc_html_e( '7 days', 'oneclicky-temporary-access' ); ?></option>
                    <option value="43200"><?php esc_html_e( '30 days', 'oneclicky-temporary-access' ); ?></option>
                    <option value="custom"><?php esc_html_e( 'Custom amount', 'oneclicky-temporary-access' ); ?></option>
                    <option value="exact"><?php esc_html_e( 'Exact date & time', 'oneclicky-temporary-access' ); ?></option>
                </select>
            </div>
            <div class="amta-duration-extra amta-duration-custom" hidden><label for="amta-custom-<?php echo esc_attr( $suffix ); ?>"><?php esc_html_e( 'Custom duration', 'oneclicky-temporary-access' ); ?></label><div class="amta-duration-line"><input id="amta-custom-<?php echo esc_attr( $suffix ); ?>" type="number" min="1" max="525600" name="amta_custom_value" value="2" disabled><select name="amta_custom_unit" disabled><option value="minutes"><?php esc_html_e( 'Minutes', 'oneclicky-temporary-access' ); ?></option><option value="hours" selected><?php esc_html_e( 'Hours', 'oneclicky-temporary-access' ); ?></option><option value="days"><?php esc_html_e( 'Days', 'oneclicky-temporary-access' ); ?></option></select></div></div>
            <div class="amta-duration-extra amta-duration-exact" hidden><label for="amta-exact-<?php echo esc_attr( $suffix ); ?>"><?php esc_html_e( 'Expires on (site timezone)', 'oneclicky-temporary-access' ); ?></label><input id="amta-exact-<?php echo esc_attr( $suffix ); ?>" type="datetime-local" name="amta_exact_time" disabled><small><?php echo esc_html( wp_timezone_string() ); ?></small></div>
            <small class="amta-duration-hint"><?php esc_html_e( 'Allowed: 5 minutes to 365 days.', 'oneclicky-temporary-access' ); ?></small>
        </div>
        <?php
    }

    private static function date( $timestamp ) {
        return $timestamp ? wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $timestamp ) : '—';
    }

    private static function status( $record ) {
        if ( 'active' === $record->status && (int) $record->expires_at <= time() ) {
            return 'expired';
        }
        return $record->status;
    }

    public static function render() {
        if ( AMTA_Hardening::is_temporary( get_current_user_id() ) || ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have permission to view this page.', 'oneclicky-temporary-access' ) );
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only URL navigation/filter; no state change.
        $view = isset( $_GET['view'] ) ? sanitize_key( wp_unslash( $_GET['view'] ) ) : 'dashboard';
        if ( ! in_array( $view, array( 'dashboard', 'create', 'links', 'bulk', 'activity', 'security' ), true ) ) {
            $view = 'dashboard';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only URL navigation/filter; no state change.
        $filter_status = isset( $_GET['amta_status'] ) ? sanitize_key( wp_unslash( $_GET['amta_status'] ) ) : 'all';
        if ( ! in_array( $filter_status, array( 'all', 'active', 'expired', 'revoked' ), true ) ) {
            $filter_status = 'all';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only URL navigation/filter; no state change.
        $search = isset( $_GET['s'] ) && is_string( $_GET['s'] ) ? substr( sanitize_text_field( wp_unslash( $_GET['s'] ) ), 0, 100 ) : '';
        $counts = AMTA_Storage::counts();
        $total = AMTA_Storage::total();
        $per_page = 20;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only URL navigation/filter; no state change.
        $current_page = isset( $_GET['paged'] ) ? max( 1, absint( wp_unslash( $_GET['paged'] ) ) ) : 1;
        $filtered_total = 'links' === $view ? AMTA_Storage::filtered_total( $filter_status, $search ) : 0;
        $rows = 'links' === $view ? AMTA_Storage::page( $per_page, ( $current_page - 1 ) * $per_page, $filter_status, $search ) : array();
        // Newly issued encrypted tokens can be revealed only to a real owner while valid.
        // Pair each URL with its exact invitation ID, not name or email (both can repeat).
        $new_links_by_id = array();
        if ( 'links' === $view && self::$new_links ) {
            foreach ( self::$new_links as $fresh_link ) {
                $new_links_by_id[ (int) $fresh_link['id'] ] = $fresh_link;
            }
            $visible_ids = array_map( static function ( $row ) { return (int) $row->id; }, $rows );
            foreach ( array_reverse( array_keys( $new_links_by_id ) ) as $fresh_id ) {
                if ( ! in_array( (int) $fresh_id, $visible_ids, true ) ) {
                    $fresh_row = AMTA_Storage::get( (int) $fresh_id );
                    if ( $fresh_row ) {
                        array_unshift( $rows, $fresh_row );
                        if ( count( $rows ) > $per_page ) {
                            array_pop( $rows );
                        }
                    }
                }
            }
        }
        $events = AMTA_Storage::latest_events();
        $roles = get_editable_roles();
        $role_names = wp_roles()->get_names();
        $status_labels = array(
            'active' => __( 'Valid access', 'oneclicky-temporary-access' ),
            'expired' => __( 'Expired', 'oneclicky-temporary-access' ),
            'revoked' => __( 'Revoked', 'oneclicky-temporary-access' ),
        );
        $event_labels = array(
            'created' => __( 'Created', 'oneclicky-temporary-access' ),
            'redeemed' => __( 'Redeemed', 'oneclicky-temporary-access' ),
            'dashboard' => __( 'Dashboard entered', 'oneclicky-temporary-access' ),
            'revoked' => __( 'Revoked', 'oneclicky-temporary-access' ),
            'expired' => __( 'Expired', 'oneclicky-temporary-access' ),
            'extended' => __( 'Expiry updated', 'oneclicky-temporary-access' ),
            'permission_granted' => __( 'Permission unlocked temporarily', 'oneclicky-temporary-access' ),
            'permission_locked' => __( 'Permission locked', 'oneclicky-temporary-access' ),
            'locks_saved' => __( 'Feature locks saved. Unselected WordPress permissions remain unchanged.', 'oneclicky-temporary-access' ),
            'locks_failed' => __( 'Could not save the locks. Check the invitation and submitted selections.', 'oneclicky-temporary-access' ),
            'restored' => __( 'Restored with new link', 'oneclicky-temporary-access' ),
            'locks_updated' => __( 'Feature locks updated', 'oneclicky-temporary-access' ),
            'content_changed' => __( 'Post or page saved', 'oneclicky-temporary-access' ),
            'content_deleted' => __( 'Post or page deleted', 'oneclicky-temporary-access' ),
            'plugin_enabled' => __( 'Plugin activated', 'oneclicky-temporary-access' ),
            'plugin_disabled' => __( 'Plugin deactivated', 'oneclicky-temporary-access' ),
            'role_changed' => __( 'User role changed', 'oneclicky-temporary-access' ),
            'user_created' => __( 'WordPress user created', 'oneclicky-temporary-access' ),
            'theme_switched' => __( 'Theme switched', 'oneclicky-temporary-access' ),
            'site_setting' => __( 'Site setting modified', 'oneclicky-temporary-access' ),
            'emergency_on' => __( 'Emergency Lock enabled', 'oneclicky-temporary-access' ),
            'emergency_off' => __( 'Emergency Lock disabled', 'oneclicky-temporary-access' ),
        );
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only URL navigation/filter; no state change.
        $notice = isset( $_GET['amta_notice'] ) ? sanitize_key( wp_unslash( $_GET['amta_notice'] ) ) : '';
        ?>
<div class="wrap amta-wrap">
    <header class="amta-header">
        <div class="amta-logo"><span class="dashicons dashicons-shield-alt" aria-hidden="true"></span></div>
        <div class="amta-heading"><div class="amta-eyebrow"><?php esc_html_e( 'SECURE ACCESS CONTROL', 'oneclicky-temporary-access' ); ?></div>
            <h1><?php esc_html_e( 'OneClicky', 'oneclicky-temporary-access' ); ?><span class="amta-version">v<?php echo esc_html( AMTA_VERSION ); ?></span></h1>
            <p><?php esc_html_e( 'Share access, never passwords. Every invitation is temporary and revocable.', 'oneclicky-temporary-access' ); ?></p>
        </div>
        <div class="amta-header-actions"><a class="amta-header-link" href="<?php echo esc_url( admin_url( 'admin.php?page=oneclicky-temporary-access&view=create' ) ); ?>"><span class="dashicons dashicons-plus-alt2" aria-hidden="true"></span><?php esc_html_e( 'New access', 'oneclicky-temporary-access' ); ?></a><a class="amta-header-link" href="<?php echo esc_url( admin_url( 'admin.php?page=oneclicky-temporary-access&view=links' ) ); ?>"><span class="dashicons dashicons-admin-links" aria-hidden="true"></span><?php esc_html_e( 'All links', 'oneclicky-temporary-access' ); ?></a></div>
    </header>

    <nav class="amta-primary-nav" aria-label="<?php esc_attr_e( 'OneClicky navigation', 'oneclicky-temporary-access' ); ?>">
        <?php $tabs = array( 'dashboard' => array( 'dashicons-dashboard', __( 'Dashboard', 'oneclicky-temporary-access' ) ), 'create' => array( 'dashicons-plus-alt2', __( 'Create Access', 'oneclicky-temporary-access' ) ), 'links' => array( 'dashicons-admin-links', __( 'All Links', 'oneclicky-temporary-access' ) ), 'bulk' => array( 'dashicons-groups', __( 'Bulk Access', 'oneclicky-temporary-access' ) ), 'activity' => array( 'dashicons-list-view', __( 'Activity', 'oneclicky-temporary-access' ) ), 'security' => array( 'dashicons-shield', __( 'Security', 'oneclicky-temporary-access' ) ) ); ?>
        <?php foreach ( $tabs as $slug => $entry ) : ?><a class="amta-nav-link <?php echo $view === $slug ? 'is-active' : ''; ?>" <?php if ( $view === $slug ) : ?>aria-current="page"<?php endif; ?> href="<?php echo esc_url( add_query_arg( 'view', $slug, admin_url( 'admin.php?page=oneclicky-temporary-access' ) ) ); ?>"><span class="dashicons <?php echo esc_attr( $entry[0] ); ?>" aria-hidden="true"></span><?php echo esc_html( $entry[1] ); ?><?php if ( 'links' === $slug ) : ?><span class="amta-nav-count"><?php echo esc_html( (string) $total ); ?></span><?php endif; ?></a><?php endforeach; ?>
    </nav>

    <?php if ( in_array( $notice, array( 'emergency_on', 'emergency_off', 'emergency_failed', 'settings_saved', 'mail_accepted', 'mail_failed' ), true ) ) : ?>
        <?php $messages = array( 'emergency_on' => __( 'Emergency Lock enabled: invitations and sessions revoked. New invitations are blocked.', 'oneclicky-temporary-access' ), 'emergency_off' => __( 'Emergency Lock disabled. Old invitations remain revoked; issue new links.', 'oneclicky-temporary-access' ), 'emergency_failed' => __( 'Could not confirm that all old invitations are revoked. Lock remains enabled.', 'oneclicky-temporary-access' ), 'settings_saved' => __( 'Alert preferences saved.', 'oneclicky-temporary-access' ), 'mail_accepted' => __( 'WordPress accepted the test email. Check your inbox and spam folder; delivery is not guaranteed.', 'oneclicky-temporary-access' ), 'mail_failed' => __( 'WordPress rejected the test email. Check your SMTP plugin configuration and mail logs.', 'oneclicky-temporary-access' ) ); ?>
        <div class="amta-notice <?php echo in_array( $notice, array( 'emergency_failed', 'mail_failed' ), true ) ? 'amta-error' : 'amta-success'; ?>" role="status"><?php echo esc_html( $messages[ $notice ] ); ?></div>
    <?php endif; ?>
    <?php if ( self::$error ) : ?><div class="amta-notice amta-error" role="alert"><?php echo esc_html( self::$error ); ?></div><?php endif; ?>
    <?php if ( 'locks_saved' === $notice ) : ?><div class="amta-notice amta-success" role="status"><?php esc_html_e( 'Custom feature locks saved for this invitation. Unticked functions remain available according to the original WordPress role.', 'oneclicky-temporary-access' ); ?></div><?php endif; ?>
    <?php if ( 'locks_failed' === $notice ) : ?><div class="amta-notice amta-error" role="alert"><?php esc_html_e( 'Unable to update feature locks. Confirm the invitation is still active and try again.', 'oneclicky-temporary-access' ); ?></div><?php endif; ?>
    <?php if ( 'revoked' === $notice ) : ?><div class="amta-notice amta-success" role="status"><?php esc_html_e( 'Temporary access revoked. Existing sessions have been terminated.', 'oneclicky-temporary-access' ); ?></div><?php endif; ?>
    <?php if ( 'updated' === $notice ) : ?><div class="amta-notice amta-success" role="status"><?php esc_html_e( 'The expiration time was updated.', 'oneclicky-temporary-access' ); ?></div><?php endif; ?>
    <?php if ( 'update_failed' === $notice ) : ?><div class="amta-notice amta-error" role="alert"><?php esc_html_e( 'Could not change this expiry. Only active links can be edited, within 5 minutes to 365 days.', 'oneclicky-temporary-access' ); ?></div><?php endif; ?>
    <?php if ( 'deleted' === $notice ) : ?><div class="amta-notice amta-success" role="status"><?php esc_html_e( 'Invitation deleted. Its access is disabled and its audit record is retained.', 'oneclicky-temporary-access' ); ?></div><?php endif; ?>
    <?php if ( 'unchanged' === $notice ) : ?><div class="amta-notice" role="status"><?php esc_html_e( 'This access was already closed or could not be found.', 'oneclicky-temporary-access' ); ?></div><?php endif; ?>
    <?php if ( self::$new_links ) : ?>
        <div class="amta-notice amta-success" role="status">
            <strong><?php echo esc_html( self::$info ); ?></strong>
            <p><?php esc_html_e( 'Your new secure links are shown INSIDE their matching invitation cards below. You can copy unused active links again after refreshing; they are encrypted at rest.', 'oneclicky-temporary-access' ); ?></p>
        </div>
    <?php endif; ?>

    <?php if ( AMTA_Guard::locked() ) : ?><div class="amta-notice amta-error" role="alert"><strong><?php esc_html_e( 'Emergency Lock is ON.', 'oneclicky-temporary-access' ); ?></strong> <?php esc_html_e( 'All temporary sessions are blocked. Manage it in Security.', 'oneclicky-temporary-access' ); ?></div><?php endif; ?>

    <?php if ( 'dashboard' === $view ) : ?>
    <section class="amta-stats" aria-label="<?php esc_attr_e( 'Access overview', 'oneclicky-temporary-access' ); ?>">
        <div class="amta-stat"><span class="amta-stat-label"><span class="amta-dot amta-green"></span><?php esc_html_e( 'Valid invitations', 'oneclicky-temporary-access' ); ?></span><strong><?php echo esc_html( number_format_i18n( $counts['active'] ) ); ?></strong><small><?php esc_html_e( 'Includes invitations still Pending', 'oneclicky-temporary-access' ); ?></small></div>
        <div class="amta-stat"><span class="amta-stat-label"><span class="amta-dot amta-orange"></span><?php esc_html_e( 'Expired', 'oneclicky-temporary-access' ); ?></span><strong><?php echo esc_html( number_format_i18n( $counts['expired'] ) ); ?></strong><small><?php esc_html_e( 'Automatically blocked', 'oneclicky-temporary-access' ); ?></small></div>
        <div class="amta-stat"><span class="amta-stat-label"><span class="amta-dot amta-gray"></span><?php esc_html_e( 'Revoked', 'oneclicky-temporary-access' ); ?></span><strong><?php echo esc_html( number_format_i18n( $counts['revoked'] ) ); ?></strong><small><?php esc_html_e( 'Manually disabled', 'oneclicky-temporary-access' ); ?></small></div>
        <div class="amta-stat"><span class="amta-stat-label"><span class="dashicons dashicons-admin-users" aria-hidden="true"></span><?php esc_html_e( 'All invitations', 'oneclicky-temporary-access' ); ?></span><strong><?php echo esc_html( number_format_i18n( $total ) ); ?></strong><small><?php esc_html_e( 'Visible invitations', 'oneclicky-temporary-access' ); ?></small></div>
    </section>

    <?php endif; ?>
    <?php if ( 'dashboard' === $view || 'create' === $view ) : ?>
    <div class="amta-columns">
        <section class="amta-panel" id="amta-create">
            <div class="amta-panel-heading"><div><span class="amta-overline"><?php esc_html_e( 'CREATE', 'oneclicky-temporary-access' ); ?></span><h2><?php esc_html_e( 'Grant temporary access', 'oneclicky-temporary-access' ); ?></h2><p><?php esc_html_e( 'A dedicated user account is created for each invitation.', 'oneclicky-temporary-access' ); ?></p></div></div>
            <?php if ( current_user_can( 'create_users' ) && current_user_can( 'promote_users' ) ) : ?>
            <form method="post" action="<?php echo esc_url( admin_url( 'admin.php?page=oneclicky-temporary-access&view=links' ) ); ?>" class="amta-form">
                <input type="hidden" name="amta_action" value="create">
                <?php wp_nonce_field( 'amta_create', 'amta_nonce' ); ?>
                <div class="amta-field"><label for="amta-name"><?php esc_html_e( 'Recipient name', 'oneclicky-temporary-access' ); ?> <span class="amta-required">*</span></label><input id="amta-name" class="regular-text" name="amta_name" maxlength="100" required placeholder="<?php esc_attr_e( 'e.g. Website support', 'oneclicky-temporary-access' ); ?>"><small><?php esc_html_e( 'Used as the temporary account display name.', 'oneclicky-temporary-access' ); ?></small></div>
                <div class="amta-field"><label for="amta-email"><?php esc_html_e( 'Recipient email', 'oneclicky-temporary-access' ); ?> <span class="amta-required">*</span></label><input id="amta-email" type="email" name="amta_email" class="regular-text" maxlength="254" required placeholder="name@example.com"><small><?php esc_html_e( 'Required. Existing WordPress user emails and repeated recipients are supported; their original accounts are never changed.', 'oneclicky-temporary-access' ); ?></small></div>
                <div class="amta-form-grid">
                    <div class="amta-field"><label for="amta-role"><?php esc_html_e( 'User role', 'oneclicky-temporary-access' ); ?></label><select id="amta-role" name="amta_role" required>
                        <?php foreach ( $roles as $slug => $info ) : ?>
                            <?php if ( AMTA_Hardening::ROLE === $slug ) { continue; } ?>
                            <option value="<?php echo esc_attr( $slug ); ?>" <?php selected( $slug, 'editor' ); ?>><?php echo esc_html( AMTA_Hardening::role_label( $slug, translate_user_role( $info['name'] ) ) ); ?></option>
                        <?php endforeach; ?>
                    </select></div>
                    <?php self::duration_fields( 'single' ); ?>
                </div>
                <div class="amta-field"><label for="amta-uses"><?php esc_html_e( 'Link use limit', 'oneclicky-temporary-access' ); ?></label><select id="amta-uses" name="amta_max_uses"><option value="1"><?php esc_html_e( 'One-time link (recommended)', 'oneclicky-temporary-access' ); ?></option><option value="3"><?php esc_html_e( '3 logins', 'oneclicky-temporary-access' ); ?></option><option value="5"><?php esc_html_e( '5 logins', 'oneclicky-temporary-access' ); ?></option><option value="10"><?php esc_html_e( '10 logins', 'oneclicky-temporary-access' ); ?></option></select><small><?php esc_html_e( 'This limits link redemptions; existing sessions still work until the expiry or revocation.', 'oneclicky-temporary-access' ); ?></small></div>
                <label class="amta-email-opt"><input type="checkbox" name="amta_require_otp" value="1"> <span><?php esc_html_e( 'Require recipient email OTP before login', 'oneclicky-temporary-access' ); ?><small><?php esc_html_e( 'Optional. An eight-digit code is emailed at login. If WordPress/SMTP mail fails, the recipient cannot sign in. Test email delivery first under Security.', 'oneclicky-temporary-access' ); ?></small></span></label>
            <label class="amta-email-opt"><input type="checkbox" name="amta_send_email" value="1"> <span><?php esc_html_e( 'Also send the secure link via WordPress email', 'oneclicky-temporary-access' ); ?><small><?php esc_html_e( 'Optional. Configure working site email/SMTP. Sending does not guarantee arrival.', 'oneclicky-temporary-access' ); ?></small></span></label>
                <div id="amta-admin-warning" class="amta-admin-warning" hidden><strong><?php esc_html_e( 'Full Administrator access — security warning.', 'oneclicky-temporary-access' ); ?></strong><p><?php esc_html_e( 'This gives the normal WordPress Administrator role, including Plugins, Appearance, Users and Settings. OneClicky blocks its own standard controls, but a real Administrator can bypass plugin-level protections. Use only with highly trusted recipients.', 'oneclicky-temporary-access' ); ?></p><label><input type="checkbox" name="amta_confirm_admin" value="1"> <?php esc_html_e( 'I understand this gives full WordPress Administrator privileges and OneClicky cannot guarantee isolation.', 'oneclicky-temporary-access' ); ?></label></div>
                <button type="submit" class="button button-primary amta-submit"><span class="dashicons dashicons-lock" aria-hidden="true"></span><?php esc_html_e( 'Generate secure invitation', 'oneclicky-temporary-access' ); ?></button>
            </form>
            <?php else : ?><p><?php esc_html_e( 'Your account cannot create or assign WordPress users.', 'oneclicky-temporary-access' ); ?></p><?php endif; ?>
        </section>
        <aside class="amta-panel amta-tips"><div class="amta-panel-heading"><div><span class="amta-overline"><?php esc_html_e( 'DESIGNED FOR TRUST', 'oneclicky-temporary-access' ); ?></span><h2><?php esc_html_e( 'Security by default', 'oneclicky-temporary-access' ); ?></h2></div></div>
            <div class="amta-tip"><span class="dashicons dashicons-lock" aria-hidden="true"></span><div><strong><?php esc_html_e( 'Protected temporary accounts', 'oneclicky-temporary-access' ); ?></strong><p><?php esc_html_e( 'Temporary accounts receive their selected original WordPress roles. Administrator grants full privileges to manage other plugins, themes, users and settings. OneClicky blocks its own standard management actions, but cannot withstand a malicious full Administrator.', 'oneclicky-temporary-access' ); ?></p></div></div>
            <div class="amta-tip"><span class="dashicons dashicons-shield" aria-hidden="true"></span><div><strong><?php esc_html_e( 'No shared passwords', 'oneclicky-temporary-access' ); ?></strong><p><?php esc_html_e( 'Each recipient gets a separate WordPress identity with an unpredictable login link.', 'oneclicky-temporary-access' ); ?></p></div></div>
            <div class="amta-tip"><span class="dashicons dashicons-clock" aria-hidden="true"></span><div><strong><?php esc_html_e( 'Strict expiration', 'oneclicky-temporary-access' ); ?></strong><p><?php esc_html_e( 'Session authorization is rechecked on every request, even before the next scheduled cleanup.', 'oneclicky-temporary-access' ); ?></p></div></div>
            <div class="amta-tip"><span class="dashicons dashicons-dismiss" aria-hidden="true"></span><div><strong><?php esc_html_e( 'Instant revocation', 'oneclicky-temporary-access' ); ?></strong><p><?php esc_html_e( 'Revoke access and terminate every WordPress session associated with it.', 'oneclicky-temporary-access' ); ?></p></div></div>
            <div class="amta-tip"><span class="dashicons dashicons-visibility" aria-hidden="true"></span><div><strong><?php esc_html_e( 'Minimal activity trail', 'oneclicky-temporary-access' ); ?></strong><p><?php esc_html_e( 'Track invitation creation, redemptions, expiry and revocations. No third-party telemetry.', 'oneclicky-temporary-access' ); ?></p></div></div>
            <div class="amta-inline-note"><?php esc_html_e( 'Tip: Use the lowest role needed, select one-time use, and share the link over a trusted channel.', 'oneclicky-temporary-access' ); ?></div>
        </aside>
    </div>

    <?php endif; ?>
    <?php if ( 'bulk' === $view ) : ?>
    <section class="amta-panel amta-bulk-panel" id="amta-bulk">
        <div class="amta-panel-heading"><span class="amta-overline"><?php esc_html_e( 'BULK ACCESS', 'oneclicky-temporary-access' ); ?></span><h2><?php esc_html_e( 'Create multiple accounts at once', 'oneclicky-temporary-access' ); ?></h2><p><?php esc_html_e( 'Enter up to 20 recipients. Each person receives an independent WordPress account and separate revocable access link.', 'oneclicky-temporary-access' ); ?></p></div>
        <?php if ( current_user_can( 'create_users' ) && current_user_can( 'promote_users' ) ) : ?>
        <form method="post" action="<?php echo esc_url( admin_url( 'admin.php?page=oneclicky-temporary-access&view=links' ) ); ?>" class="amta-form amta-bulk-form">
            <input type="hidden" name="amta_action" value="create_bulk">
            <?php wp_nonce_field( 'amta_create', 'amta_nonce' ); ?>
            <div class="amta-field"><label for="amta-bulk-list"><?php esc_html_e( 'Recipients (name,email)', 'oneclicky-temporary-access' ); ?> <span class="amta-required">*</span></label><textarea id="amta-bulk-list" name="amta_bulk" maxlength="10000" rows="6" required placeholder="Alice,alice@example.com&#10;Bob,bob@example.com&#10;Support Team,alice@example.com"></textarea><small><?php esc_html_e( 'One recipient per line, separated by a comma. Repeated emails are allowed; each line creates a separate access. Quote names containing commas.', 'oneclicky-temporary-access' ); ?></small></div>
            <div class="amta-form-grid amta-bulk-grid">
                <div class="amta-field"><label for="amta-role-bulk"><?php esc_html_e( 'Role for all', 'oneclicky-temporary-access' ); ?></label><select id="amta-role-bulk" name="amta_role" required><?php foreach ( $roles as $slug => $info ) : ?>
                            <?php if ( AMTA_Hardening::ROLE === $slug ) { continue; } ?><option value="<?php echo esc_attr( $slug ); ?>" <?php selected( $slug, 'editor' ); ?>><?php echo esc_html( AMTA_Hardening::role_label( $slug, translate_user_role( $info['name'] ) ) ); ?></option><?php endforeach; ?></select></div>
                <?php self::duration_fields( 'bulk' ); ?>
                <div class="amta-field"><label for="amta-uses-bulk"><?php esc_html_e( 'Logins per link', 'oneclicky-temporary-access' ); ?></label><select id="amta-uses-bulk" name="amta_max_uses"><option value="1"><?php esc_html_e( '1 login', 'oneclicky-temporary-access' ); ?></option><option value="3"><?php esc_html_e( '3 logins', 'oneclicky-temporary-access' ); ?></option><option value="5"><?php esc_html_e( '5 logins', 'oneclicky-temporary-access' ); ?></option><option value="10"><?php esc_html_e( '10 logins', 'oneclicky-temporary-access' ); ?></option></select></div>
            </div>
                <label class="amta-email-opt"><input type="checkbox" name="amta_require_otp" value="1"> <span><?php esc_html_e( 'Require recipient email OTP before login', 'oneclicky-temporary-access' ); ?><small><?php esc_html_e( 'Optional. An eight-digit code is emailed at login. If WordPress/SMTP mail fails, the recipient cannot sign in. Test email delivery first under Security.', 'oneclicky-temporary-access' ); ?></small></span></label>
            <label class="amta-email-opt"><input type="checkbox" name="amta_send_email" value="1"> <span><?php esc_html_e( 'Also send each recipient their own link via WordPress email', 'oneclicky-temporary-access' ); ?><small><?php esc_html_e( 'Optional. Email delivery depends on your server/SMTP configuration.', 'oneclicky-temporary-access' ); ?></small></span></label>
            <div id="amta-admin-warning-bulk" class="amta-admin-warning" hidden><strong><?php esc_html_e( 'Full Administrator access — security warning.', 'oneclicky-temporary-access' ); ?></strong><p><?php esc_html_e( 'Administrator recipients receive the real WordPress Administrator role. OneClicky self-management is blocked in ordinary WordPress routes, but a full Administrator can bypass these plugin-level checks.', 'oneclicky-temporary-access' ); ?></p><label><input type="checkbox" name="amta_confirm_admin" value="1"> <?php esc_html_e( 'I understand this gives full WordPress Administrator privileges and OneClicky cannot guarantee isolation.', 'oneclicky-temporary-access' ); ?></label></div>
            <button type="submit" class="button button-primary amta-submit"><span class="dashicons dashicons-groups" aria-hidden="true"></span><?php esc_html_e( 'Generate multiple secure invitations', 'oneclicky-temporary-access' ); ?></button>
        </form>
        <?php else : ?><p><?php esc_html_e( 'Your account cannot create or assign WordPress users.', 'oneclicky-temporary-access' ); ?></p><?php endif; ?>
    </section>

    <?php endif; ?>
    <?php if ( 'links' === $view ) : ?>
    <section class="amta-panel amta-table-panel" id="amta-access-list">
        <div class="amta-panel-heading"><span class="amta-overline"><?php esc_html_e( 'LINK MANAGEMENT', 'oneclicky-temporary-access' ); ?></span><h2><?php esc_html_e( 'All invitations', 'oneclicky-temporary-access' ); ?></h2><p><?php esc_html_e( 'Manage invitations and live dashboard presence in responsive cards. Pending becomes Active & Working only when the recipient reaches the dashboard; unredeemed links are stored encrypted and are visible only to the site owner.', 'oneclicky-temporary-access' ); ?></p></div>
        <form method="get" action="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>" class="amta-filter-bar">
            <input type="hidden" name="page" value="oneclicky-temporary-access"><input type="hidden" name="view" value="links">
            <label for="amta-link-search" class="screen-reader-text"><?php esc_html_e( 'Search invitations', 'oneclicky-temporary-access' ); ?></label><input id="amta-link-search" name="s" type="search" value="<?php echo esc_attr( $search ); ?>" placeholder="<?php esc_attr_e( 'Search recipient, email or link ID', 'oneclicky-temporary-access' ); ?>">
            <label for="amta-status-filter" class="screen-reader-text"><?php esc_html_e( 'Filter invitations by status', 'oneclicky-temporary-access' ); ?></label><select id="amta-status-filter" name="amta_status"><?php foreach ( array( 'all' => __( 'All statuses', 'oneclicky-temporary-access' ) ) + $status_labels as $key => $label ) : ?><option value="<?php echo esc_attr( $key ); ?>" <?php selected( $key, $filter_status ); ?>><?php echo esc_html( $label ); ?></option><?php endforeach; ?></select>
            <button type="submit" class="button button-primary"><?php esc_html_e( 'Apply filters', 'oneclicky-temporary-access' ); ?></button><a href="<?php echo esc_url( admin_url( 'admin.php?page=oneclicky-temporary-access&view=links' ) ); ?>" class="button"><?php esc_html_e( 'Reset', 'oneclicky-temporary-access' ); ?></a>
        </form>
        <p class="amta-result-count"><?php echo esc_html( sprintf( /* translators: %d: invitations matched */ _n( '%d invitation found', '%d invitations found', $filtered_total, 'oneclicky-temporary-access' ), $filtered_total ) ); ?></p>
        <div class="amta-link-grid" data-server-now="<?php echo esc_attr( (string) time() ); ?>">
        <?php if ( ! $rows ) : ?><p class="amta-empty"><?php esc_html_e( 'No invitations match your filters.', 'oneclicky-temporary-access' ); ?></p>
        <?php else : ?><?php foreach ( $rows as $record ) : ?><?php
            $status = self::status( $record );
            $presence = AMTA_Presence::state( $record );
            $restorable = 'revoked' === $status && (int) $record->closed_at > 0 && time() <= (int) $record->closed_at + 120;
            /* translators: %s is the recipient's display name. */
            $amta_card_aria = sprintf( __( 'Invitation for %s', 'oneclicky-temporary-access' ), $record->label );
        ?>
        <article id="amta-invitation-<?php echo esc_attr( (string) $record->id ); ?>" class="amta-link-card" data-amta-access-id="<?php echo esc_attr( (string) $record->id ); ?>" aria-label="<?php echo esc_attr( $amta_card_aria ); ?>">
            <header class="amta-link-card-head">
                <div class="amta-link-avatar" aria-hidden="true"><?php echo esc_html( strtoupper( substr( (string) $record->label, 0, 1 ) ) ); ?></div>
                <div class="amta-link-person"><h3><?php echo esc_html( $record->label ); ?></h3><p><?php echo esc_html( (string) $record->recipient_email ); ?></p><small>#<?php echo esc_html( (string) $record->id ); ?> · <?php echo esc_html( self::date( $record->created_at ) ); ?></small></div>
                <span class="amta-status amta-status-<?php echo esc_attr( $presence['code'] ); ?>" data-amta-presence-status aria-live="polite"><?php echo esc_html( $presence['label'] ); ?></span>
            </header>
            <div class="amta-presence-detail" data-amta-presence-detail><span class="dashicons dashicons-chart-line" aria-hidden="true"></span><span><?php echo esc_html( $presence['detail'] ); ?></span></div>
            <div class="amta-link-meta">
                <div><span><?php esc_html_e( 'WordPress role', 'oneclicky-temporary-access' ); ?></span><strong><?php echo esc_html( AMTA_Hardening::role_label( $record->role, isset( $role_names[ $record->role ] ) ? translate_user_role( $role_names[ $record->role ] ) : $record->role ) ); ?></strong></div>
                <div><span><?php esc_html_e( 'Link redemptions', 'oneclicky-temporary-access' ); ?></span><strong><?php echo esc_html( (string) $record->uses . ' / ' . (string) $record->max_uses ); ?></strong></div>
                <div><span><?php esc_html_e( 'Valid until', 'oneclicky-temporary-access' ); ?></span><strong><?php echo esc_html( self::date( $record->expires_at ) ); ?></strong></div>
            </div>
            <?php
            $saved_url = AMTA_Vault::link( $record );
            /* translators: %d is the numeric invitation ID. */
            $amta_link_aria = sprintf( __( 'Secure link for invitation #%d', 'oneclicky-temporary-access' ), $record->id );
            ?>
            <div class="amta-invitation-credential<?php echo isset( $new_links_by_id[ (int) $record->id ] ) ? ' is-new' : ''; ?>">
                <?php if ( $saved_url ) : ?>
                    <div class="amta-credential-top"><span class="dashicons dashicons-admin-links" aria-hidden="true"></span><strong><?php esc_html_e( 'Secure invitation link', 'oneclicky-temporary-access' ); ?></strong><span class="amta-once-pill"><?php esc_html_e( 'SAVE & COPY', 'oneclicky-temporary-access' ); ?></span></div>
                    <div class="amta-copy-row">
                        <input id="amta-new-link-<?php echo esc_attr( (string) $record->id ); ?>" class="amta-generated-link" type="text" readonly autocomplete="off" spellcheck="false" value="<?php echo esc_attr( $saved_url ); ?>" aria-label="<?php echo esc_attr( $amta_link_aria ); ?>">
                        <button type="button" class="button button-primary amta-copy" data-copy="#amta-new-link-<?php echo esc_attr( (string) $record->id ); ?>"><span class="dashicons dashicons-admin-page" aria-hidden="true"></span><?php esc_html_e( 'Copy link', 'oneclicky-temporary-access' ); ?></button>
                    </div>
                    <small><?php esc_html_e( 'Available after refresh while this link is active and has remaining uses. Stored encrypted, visible only to the original site administrators. Share privately.', 'oneclicky-temporary-access' ); ?></small>
                <?php else : ?>
                    <div class="amta-credential-hidden"><span class="dashicons dashicons-lock" aria-hidden="true"></span><span><?php esc_html_e( 'Link unavailable: already used, revoked, expired, or created before encrypted-link storage was enabled. Generate a new invitation if needed.', 'oneclicky-temporary-access' ); ?></span></div>
                <?php endif; ?>
            </div>
            <?php if ( 'active' === $status ) : ?>
                <div class="amta-countdown" data-amta-countdown data-until="<?php echo esc_attr( (string) $record->expires_at ); ?>"><span class="dashicons dashicons-clock" aria-hidden="true"></span><div><small><?php esc_html_e( 'Time remaining', 'oneclicky-temporary-access' ); ?></small><strong class="amta-timer-value" role="timer" aria-live="off">—</strong></div></div>
            <?php elseif ( $restorable ) : ?>
                <div class="amta-countdown amta-countdown-restore" data-amta-countdown data-until="<?php echo esc_attr( (string) ( (int) $record->closed_at + 120 ) ); ?>"><span class="dashicons dashicons-backup" aria-hidden="true"></span><div><small><?php esc_html_e( 'Restore window remaining', 'oneclicky-temporary-access' ); ?></small><strong class="amta-timer-value" role="timer" aria-live="off">—</strong></div></div>
            <?php elseif ( 'revoked' === $status ) : ?>
                <div class="amta-closed-label"><?php esc_html_e( 'The 2-minute restore window is closed. Create a new invitation.', 'oneclicky-temporary-access' ); ?></div>
            <?php else : ?>
                <div class="amta-closed-label"><?php esc_html_e( 'This invitation is no longer active.', 'oneclicky-temporary-access' ); ?></div>
            <?php endif; ?>
            <div class="amta-card-actions">
                <?php if ( 'active' === $status ) : ?>
                    <details class="amta-card-details amta-expiry-details">
                        <summary class="button amta-action-edit"><?php esc_html_e( 'Manage time', 'oneclicky-temporary-access' ); ?></summary>
                        <form action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" method="post" class="amta-card-edit-form amta-expiry-editor" data-amta-expiry-editor data-current-until="<?php echo esc_attr( (string) $record->expires_at ); ?>" data-server-now="<?php echo esc_attr( (string) time() ); ?>">
                            <input type="hidden" name="action" value="amta_update_expiry"><input type="hidden" name="amta_id" value="<?php echo esc_attr( (string) $record->id ); ?>">
                            <?php wp_nonce_field( 'amta_expiry_' . $record->id, 'amta_nonce' ); ?>
                            <div class="amta-expiry-overview">
                                <div><small><?php esc_html_e( 'Remaining now', 'oneclicky-temporary-access' ); ?></small><strong data-amta-current-remaining>—</strong></div>
                                <div><small><?php esc_html_e( 'Current expiration', 'oneclicky-temporary-access' ); ?></small><strong><?php echo esc_html( self::date( $record->expires_at ) ); ?></strong></div>
                            </div>
                            <div class="amta-expiry-fields">
                                <label for="amta-expiry-mode-<?php echo esc_attr( (string) $record->id ); ?>"><?php esc_html_e( 'Choose new time', 'oneclicky-temporary-access' ); ?></label>
                                <select id="amta-expiry-mode-<?php echo esc_attr( (string) $record->id ); ?>" name="amta_duration" data-amta-expiry-mode>
                                    <option value="30"><?php esc_html_e( '30 minutes', 'oneclicky-temporary-access' ); ?></option>
                                    <option value="60"><?php esc_html_e( '1 hour', 'oneclicky-temporary-access' ); ?></option>
                                    <option value="120" selected><?php esc_html_e( '2 hours', 'oneclicky-temporary-access' ); ?></option>
                                    <option value="360"><?php esc_html_e( '6 hours', 'oneclicky-temporary-access' ); ?></option>
                                    <option value="720"><?php esc_html_e( '12 hours', 'oneclicky-temporary-access' ); ?></option>
                                    <option value="1440"><?php esc_html_e( '1 day', 'oneclicky-temporary-access' ); ?></option>
                                    <option value="10080"><?php esc_html_e( '7 days', 'oneclicky-temporary-access' ); ?></option>
                                    <option value="custom"><?php esc_html_e( 'Custom amount', 'oneclicky-temporary-access' ); ?></option>
                                    <option value="exact"><?php esc_html_e( 'Specific date and time', 'oneclicky-temporary-access' ); ?></option>
                                </select>
                                <div class="amta-expiry-custom" data-amta-expiry-custom hidden>
                                    <label for="amta-expiry-amount-<?php echo esc_attr( (string) $record->id ); ?>"><?php esc_html_e( 'Custom duration', 'oneclicky-temporary-access' ); ?></label>
                                    <div class="amta-duration-line"><input id="amta-expiry-amount-<?php echo esc_attr( (string) $record->id ); ?>" type="number" name="amta_custom_value" value="2" min="1" max="525600" step="1" disabled>
                                    <select name="amta_custom_unit" disabled><option value="minutes"><?php esc_html_e( 'Minutes', 'oneclicky-temporary-access' ); ?></option><option value="hours" selected><?php esc_html_e( 'Hours', 'oneclicky-temporary-access' ); ?></option><option value="days"><?php esc_html_e( 'Days', 'oneclicky-temporary-access' ); ?></option></select></div>
                                </div>
                                <div class="amta-expiry-exact" data-amta-expiry-exact hidden>
                                    <label for="amta-expiry-date-<?php echo esc_attr( (string) $record->id ); ?>"><?php esc_html_e( 'Exact expiration (site timezone)', 'oneclicky-temporary-access' ); ?></label>
                                    <input id="amta-expiry-date-<?php echo esc_attr( (string) $record->id ); ?>" type="datetime-local" name="amta_exact_time" value="<?php echo esc_attr( wp_date( 'Y-m-d\TH:i', (int) $record->expires_at ) ); ?>" disabled>
                                    <small><?php echo esc_html( wp_timezone_string() ); ?> — <?php esc_html_e( 'Date/time is checked by WordPress when you save.', 'oneclicky-temporary-access' ); ?></small>
                                </div>
                                <label for="amta-expiry-basis-<?php echo esc_attr( (string) $record->id ); ?>" data-amta-basis-wrap><?php esc_html_e( 'Apply duration to', 'oneclicky-temporary-access' ); ?>
                                    <select id="amta-expiry-basis-<?php echo esc_attr( (string) $record->id ); ?>" name="amta_expiry_basis" data-amta-expiry-basis>
                                        <option value="now" selected><?php esc_html_e( 'From now — set total time left', 'oneclicky-temporary-access' ); ?></option>
                                        <option value="current"><?php esc_html_e( 'Add to current expiration', 'oneclicky-temporary-access' ); ?></option>
                                    </select>
                                </label>
                            </div>
                            <div class="amta-expiry-preview" aria-live="off">
                                <div><small><?php esc_html_e( 'After saving — time remaining', 'oneclicky-temporary-access' ); ?></small><strong data-amta-new-remaining>—</strong></div>
                                <p data-amta-expiry-change></p>
                            </div>
                            <p class="amta-expiry-policy"><?php esc_html_e( 'Minimum 5 minutes, maximum 365 days from now. Shortening the time affects the active session immediately; expired links cannot be revived here.', 'oneclicky-temporary-access' ); ?></p>
                            <button type="submit" class="button button-primary amta-expiry-submit"><?php esc_html_e( 'Save new expiration', 'oneclicky-temporary-access' ); ?></button>
                        </form>
                    </details>
                    <form action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" method="post" class="amta-revoke-form"><input type="hidden" name="action" value="amta_revoke"><input type="hidden" name="amta_id" value="<?php echo esc_attr( (string) $record->id ); ?>"><?php wp_nonce_field( 'amta_revoke_' . $record->id, 'amta_nonce' ); ?><button class="button amta-revoke" type="submit"><?php esc_html_e( 'Revoke', 'oneclicky-temporary-access' ); ?></button></form>
                <?php elseif ( $restorable && current_user_can( 'create_users' ) && current_user_can( 'promote_users' ) ) : ?>
                    <details class="amta-card-details amta-restore-details"><summary class="button amta-action-restore"><?php esc_html_e( 'Restore / renew', 'oneclicky-temporary-access' ); ?></summary><form method="post" action="<?php echo esc_url( admin_url( 'admin.php?page=oneclicky-temporary-access&view=links' ) ); ?>" class="amta-card-edit-form amta-restore-form"><input type="hidden" name="amta_action" value="restore"><input type="hidden" name="amta_id" value="<?php echo esc_attr( (string) $record->id ); ?>"><?php wp_nonce_field( 'amta_restore_' . $record->id, 'amta_nonce' ); ?><p><?php esc_html_e( 'A brand-new secure link is generated. Old links and sessions stay invalid.', 'oneclicky-temporary-access' ); ?></p><label class="amta-restore-checkbox"><input type="checkbox" name="amta_extend_expiry" value="1" <?php checked( (int) $record->expires_at < time() + 300 ); ?>> <?php esc_html_e( 'Set a new expiry', 'oneclicky-temporary-access' ); ?></label><label><?php esc_html_e( 'Expiry (site timezone)', 'oneclicky-temporary-access' ); ?><input name="amta_exact_time" type="datetime-local" value="<?php echo esc_attr( wp_date( 'Y-m-d\TH:i', max( time() + HOUR_IN_SECONDS, (int) $record->expires_at ) ) ); ?>"></label><?php if ( 'administrator' === $record->role ) : ?><label class="amta-restore-checkbox"><input type="checkbox" name="amta_confirm_admin" value="1" required> <?php esc_html_e( 'I confirm that I want to restore full Administrator access.', 'oneclicky-temporary-access' ); ?></label><?php endif; ?><button class="button button-primary" type="submit"><?php esc_html_e( 'Confirm restore', 'oneclicky-temporary-access' ); ?></button></form></details>
                <?php endif; ?>
                <form action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" method="post" class="amta-delete-form"><input type="hidden" name="action" value="amta_delete"><input type="hidden" name="amta_id" value="<?php echo esc_attr( (string) $record->id ); ?>"><?php wp_nonce_field( 'amta_delete_' . $record->id, 'amta_nonce' ); ?><button class="button amta-delete" type="submit"><?php esc_html_e( 'Delete permanently', 'oneclicky-temporary-access' ); ?></button></form>
            </div>

            <?php if ( 'active' === $status && current_user_can( 'manage_options' ) && current_user_can( 'create_users' ) && current_user_can( 'promote_users' ) ) : ?>
            <?php
                $locks = AMTA_Access_Locks::read( (int) $record->user_id, (int) $record->id );
                $lock_count = count( $locks['groups'] ) + count( $locks['extra_caps'] );
                /* translators: %d is the number of locked features. */
                $amta_locks_label = $lock_count ? sprintf( _n( '%d locked', '%d locked', $lock_count, 'oneclicky-temporary-access' ), $lock_count ) : __( 'All standard permissions available', 'oneclicky-temporary-access' );
            ?>
            <details class="amta-feature-locks">
                <summary><span class="dashicons dashicons-lock" aria-hidden="true"></span><strong><?php esc_html_e( 'Custom Feature Locks', 'oneclicky-temporary-access' ); ?></strong><span class="amta-feature-lock-count"><?php echo esc_html( $amta_locks_label ); ?></span></summary>
                <div class="amta-feature-lock-body">
                    <p><?php esc_html_e( 'The original WordPress Dashboard and role stay unchanged. Check only features you want to BLOCK for this invitation. Unticked features work normally. OneClicky controls remain protected.', 'oneclicky-temporary-access' ); ?></p>
                    <form action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" method="post" class="amta-feature-lock-form">
                        <input type="hidden" name="action" value="amta_save_locks">
                        <input type="hidden" name="amta_id" value="<?php echo esc_attr( (string) $record->id ); ?>">
                        <?php wp_nonce_field( 'amta_feature_locks_' . $record->id, 'amta_nonce' ); ?>
                        <div class="amta-feature-lock-toolbar">
                            <button class="button amta-lock-select-all" type="button"><?php esc_html_e( 'Select all core groups', 'oneclicky-temporary-access' ); ?></button>
                            <button class="button amta-lock-clear" type="button"><?php esc_html_e( 'Unlock all', 'oneclicky-temporary-access' ); ?></button>
                        </div>
                        <div class="amta-feature-lock-choices">
                            <?php foreach ( AMTA_Access_Locks::groups() as $group_key => $config ) : ?>
                                <label class="amta-feature-lock-choice"><input type="checkbox" name="amta_locked_groups[]" value="<?php echo esc_attr( $group_key ); ?>" <?php checked( in_array( $group_key, $locks['groups'], true ) ); ?>> <span><?php echo esc_html( $config['title'] ); ?></span></label>
                            <?php endforeach; ?>
                        </div>
                        <?php $extra_caps = AMTA_Access_Locks::advanced_caps(); ?>
                        <?php if ( $extra_caps ) : ?>
                            <details class="amta-extra-caps"><summary><?php esc_html_e( 'Advanced: lock individual plugin capabilities', 'oneclicky-temporary-access' ); ?> (<?php echo esc_html( (string) count( $extra_caps ) ); ?>)</summary>
                                <p><?php esc_html_e( 'Select additional Administrator capabilities registered by third-party plugins. Not every plugin action has a capability check.', 'oneclicky-temporary-access' ); ?></p>
                                <input type="search" class="amta-extra-cap-search" placeholder="<?php esc_attr_e( 'Search capabilities', 'oneclicky-temporary-access' ); ?>" aria-label="<?php esc_attr_e( 'Filter capability checkboxes', 'oneclicky-temporary-access' ); ?>">
                                <div class="amta-extra-cap-list">
                                    <?php foreach ( $extra_caps as $cap ) : ?><label class="amta-extra-cap-item"><input type="checkbox" name="amta_locked_caps[]" value="<?php echo esc_attr( $cap ); ?>" <?php checked( in_array( $cap, $locks['extra_caps'], true ) ); ?>> <code><?php echo esc_html( $cap ); ?></code></label><?php endforeach; ?>
                                </div>
                            </details>
                        <?php endif; ?>
                        <div class="amta-permanent-protection"><span class="dashicons dashicons-shield" aria-hidden="true"></span><span><?php esc_html_e( 'OneClicky management is always protected from temporary users. This lock is not configurable.', 'oneclicky-temporary-access' ); ?></span></div>
                        <button type="submit" class="button button-primary amta-save-feature-locks"><?php esc_html_e( 'Save lock / unlock settings', 'oneclicky-temporary-access' ); ?></button>
                    </form>
                </div>
            </details>
            <?php endif; ?>
        </article>
        <?php endforeach; ?><?php endif; ?>
        </div>
        <?php if ( $filtered_total > $per_page ) : ?><div class="amta-pagination"><?php echo wp_kses_post( paginate_links( array( 'base' => add_query_arg( array( 'paged' => '%#%', 'amta_status' => $filter_status, 's' => $search ), admin_url( 'admin.php?page=oneclicky-temporary-access&view=links' ) ), 'format' => '', 'current' => $current_page, 'total' => ceil( $filtered_total / $per_page ), 'prev_text' => '&laquo;', 'next_text' => '&raquo;' ) ) ); ?></div><?php endif; ?>
    </section>

    <?php endif; ?>
    <?php if ( 'security' === $view ) : ?>
    <section class="amta-panel amta-security-center">
        <div class="amta-panel-heading"><div><span class="amta-overline"><?php esc_html_e( 'SECURITY CENTER', 'oneclicky-temporary-access' ); ?></span><h2><?php esc_html_e( 'Emergency protection & email health', 'oneclicky-temporary-access' ); ?></h2><p><?php esc_html_e( 'Site-owner-only controls. Emergency Lock permanently revokes existing invitations; switching it off does not resurrect old links.', 'oneclicky-temporary-access' ); ?></p></div></div>
        <div class="amta-security-grid">
            <div class="amta-security-tile">
                <h3><span class="dashicons dashicons-warning" aria-hidden="true"></span> <?php esc_html_e( 'Emergency Lock', 'oneclicky-temporary-access' ); ?></h3>
                <p class="amta-security-status <?php echo AMTA_Guard::locked() ? 'amta-is-locked' : 'amta-is-unlocked'; ?>"><?php echo AMTA_Guard::locked() ? esc_html__( 'ON — invitations blocked', 'oneclicky-temporary-access' ) : esc_html__( 'OFF — normal operation', 'oneclicky-temporary-access' ); ?></p>
                <p><?php esc_html_e( 'Immediately stop every temporary session and invitation, and block all new invitations and restores.', 'oneclicky-temporary-access' ); ?></p>
                <?php if ( current_user_can( 'create_users' ) && current_user_can( 'promote_users' ) ) : ?>
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="amta-emergency-form"><input type="hidden" name="action" value="amta_emergency"><input type="hidden" name="amta_mode" value="<?php echo AMTA_Guard::locked() ? 'disable' : 'enable'; ?>"><?php wp_nonce_field( 'amta_emergency', 'amta_nonce' ); ?>
                    <button class="button <?php echo AMTA_Guard::locked() ? 'button-primary' : 'amta-danger-button'; ?>" type="submit" data-amta-emergency-confirm="<?php esc_attr_e( 'WARNING: This permanently revokes ALL temporary invitations and signs out temporary users. Continue?', 'oneclicky-temporary-access' ); ?>"><?php echo AMTA_Guard::locked() ? esc_html__( 'Disable Emergency Lock', 'oneclicky-temporary-access' ) : esc_html__( 'Activate Emergency Lock — revoke all', 'oneclicky-temporary-access' ); ?></button>
                </form><?php endif; ?>
            </div>
            <div class="amta-security-tile"><h3><span class="dashicons dashicons-email-alt" aria-hidden="true"></span> <?php esc_html_e( 'SMTP / WordPress Mail Test', 'oneclicky-temporary-access' ); ?></h3>
                <p><?php esc_html_e( 'Sends one test email to the WordPress Administration Email Address only. A successful send means mail was accepted, not necessarily delivered.', 'oneclicky-temporary-access' ); ?></p>
                <p><strong><?php echo esc_html( (string) get_option( 'admin_email' ) ); ?></strong></p>
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="amta_mail_test"><?php wp_nonce_field( 'amta_mail_test', 'amta_nonce' ); ?><button type="submit" class="button button-secondary"><?php esc_html_e( 'Send test email', 'oneclicky-temporary-access' ); ?></button></form>
                <details class="amta-smtp-help"><summary><?php esc_html_e( 'Email accepted but not arriving? Setup checklist', 'oneclicky-temporary-access' ); ?></summary>
                    <ol>
                        <li><?php esc_html_e( 'Set up a trusted SMTP or transactional email provider using a mail plugin (for example, the GoSMTP plugin already installed on your site).', 'oneclicky-temporary-access' ); ?></li>
                        <li><?php esc_html_e( 'Use a sender address on a domain you control, then verify the provider credentials and From address.', 'oneclicky-temporary-access' ); ?></li>
                        <li><?php esc_html_e( 'Configure SPF and DKIM for the sender domain; DMARC is also recommended.', 'oneclicky-temporary-access' ); ?></li>
                        <li><?php esc_html_e( 'Send a test, inspect inbox and spam, and check the provider delivery logs before enabling email OTP.', 'oneclicky-temporary-access' ); ?></li>
                    </ol><p><?php esc_html_e( 'First open GoSMTP > Settings, configure a real mail provider, then GoSMTP > Test mail and check the recipient inbox and delivery logs. A successful wp_mail() return does NOT mean the recipient received the message. This panel cannot configure the mail server. Never share SMTP credentials.', 'oneclicky-temporary-access' ); ?></p>
                </details>
            </div>
            <div class="amta-security-tile"><h3><span class="dashicons dashicons-bell" aria-hidden="true"></span> <?php esc_html_e( 'Email security alerts', 'oneclicky-temporary-access' ); ?></h3>
                <p><?php esc_html_e( 'Notify the site administration address for temporary logins and sensitive changes (plugin toggles, role changes, important site settings). Alerts are throttled.', 'oneclicky-temporary-access' ); ?></p>
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="amta_alert_settings"><?php wp_nonce_field( 'amta_alert_settings', 'amta_nonce' ); ?><label><input type="checkbox" name="amta_alerts_enabled" value="1" <?php checked( '1', (string) get_option( 'amta_security_alerts', '1' ) ); ?>> <?php esc_html_e( 'Enable security alert emails', 'oneclicky-temporary-access' ); ?></label><p><button type="submit" class="button button-primary"><?php esc_html_e( 'Save alert settings', 'oneclicky-temporary-access' ); ?></button></p></form>
            </div>
            <div class="amta-security-tile"><h3><span class="dashicons dashicons-shield-alt" aria-hidden="true"></span> <?php esc_html_e( 'Email OTP (optional)', 'oneclicky-temporary-access' ); ?></h3>
                <p><?php esc_html_e( 'When creating an invitation, optionally require an eight-digit email code before first login. Codes expire after 10 minutes with limited attempts. Verify SMTP delivery before enabling.', 'oneclicky-temporary-access' ); ?></p>
                <p><?php esc_html_e( 'OTP is tied to the invitation account and cannot be used to sign into an existing WordPress account. If SMTP is unavailable, do not disable OTP on a shared link: revoke that invitation and create a new non-OTP invitation only for a trusted recipient, then share it privately.', 'oneclicky-temporary-access' ); ?></p>
            </div>
        </div>
    </section>
    <?php endif; ?>
    <?php if ( 'activity' === $view ) : ?>
    <section class="amta-panel amta-activity"><div class="amta-panel-heading"><div><span class="amta-overline"><?php esc_html_e( 'AUDIT', 'oneclicky-temporary-access' ); ?></span><h2><?php esc_html_e( 'Recent activity', 'oneclicky-temporary-access' ); ?></h2><p><?php esc_html_e( 'Recent events. Activity metadata is deleted after 90 days.', 'oneclicky-temporary-access' ); ?></p></div></div>
        <?php if ( ! $events ) : ?><p class="amta-empty"><?php esc_html_e( 'Nothing to report yet.', 'oneclicky-temporary-access' ); ?></p><?php else : ?><div class="amta-event-list"><?php foreach ( $events as $event ) : ?>
        <div class="amta-event"><span class="amta-event-mark amta-event-<?php echo esc_attr( $event->event ); ?>" aria-hidden="true"></span><span><?php echo esc_html( sprintf( /* translators: 1: event name; 2: access identifier */ __( '%1$s invitation #%2$d', 'oneclicky-temporary-access' ), isset( $event_labels[ $event->event ] ) ? $event_labels[ $event->event ] : $event->event, (int) $event->access_id ) ); ?></span><?php if ( ! empty( $event->details ) ) : ?><small class="amta-event-details"><?php $payload = json_decode( $event->details, true ); echo esc_html( is_array( $payload ) ? implode( ' · ', array_map( static function ( $k, $v ) { return sanitize_key( (string) $k ) . ': ' . ( is_scalar( $v ) ? sanitize_text_field( (string) $v ) : '[data]' ); }, array_keys( $payload ), array_values( $payload ) ) ) : '' ); ?></small><?php endif; ?><time><?php echo esc_html( self::date( $event->created_at ) ); ?></time></div>
        <?php endforeach; ?></div><?php endif; ?>
    </section>
    <?php endif; ?>
    <footer class="amta-footer"><?php esc_html_e( 'OneClicky Temporary Access — private by design. No account or analytics service required.', 'oneclicky-temporary-access' ); ?></footer>
</div>
        <?php
    }
}
