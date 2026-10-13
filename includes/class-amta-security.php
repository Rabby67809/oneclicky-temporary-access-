<?php
/** Token exchange and server-side access enforcement. */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class AMTA_Security {
    public static function init() {
        add_action( 'login_init', array( __CLASS__, 'handle_invitation' ) );
        add_filter( 'determine_current_user', array( __CLASS__, 'check_session' ), 99 );
        add_filter( 'authenticate', array( __CLASS__, 'block_password_login' ), 99, 3 );
        add_filter( 'allow_password_reset', array( __CLASS__, 'block_password_reset' ), 10, 2 );
        add_action( 'wp_logout', array( __CLASS__, 'clear_session_marker' ) );
    }

    public static function digest( $token ) {
        return hash_hmac( 'sha256', $token, wp_salt( 'auth' ) );
    }

    /** Core uses this filter to determine the user for ordinary and REST requests. */
    public static function check_session( $user_id ) {
        if ( ! is_numeric( $user_id ) || (int) $user_id <= 0 ) {
            return $user_id;
        }
        $access_id = absint( get_user_meta( (int) $user_id, 'amta_access_id', true ) );
        if ( ! $access_id ) {
            return $user_id;
        }
        $record = AMTA_Storage::get_for_user( (int) $user_id, $access_id );
        if ( ! AMTA_Storage::is_live( $record ) ) {
            // Also covers sessions issued by earlier OneClicky versions.
            self::set_session_marker( $access_id, (int) $user_id );
            if ( $record && 'active' === $record->status && ! AMTA_Guard::locked() ) {
                AMTA_Storage::close( $record->id, 'expired' );
            }
            return 0;
        }
        return $user_id;
    }

    public static function block_password_login( $user, $username, $password ) {
        if ( $user instanceof WP_User && get_user_meta( $user->ID, 'amta_access_id', true ) ) {
            return new WP_Error( 'amta_link_only', __( 'This temporary account can only be accessed using its invitation link.', 'oneclicky-temporary-access' ) );
        }
        return $user;
    }

    public static function block_password_reset( $allowed, $user_id ) {
        if ( get_user_meta( (int) $user_id, 'amta_access_id', true ) ) {
            return false;
        }
        return $allowed;
    }

    /** A deactivated/revoked account loses both sessions and assigned role. */
    public static function disable_account( $record ) {
        $user_id = (int) $record->user_id;
        if ( (int) get_user_meta( $user_id, 'amta_access_id', true ) !== (int) $record->id ) {
            return;
        }
        $user = get_userdata( $user_id );
        if ( $user ) {
            WP_Session_Tokens::get_instance( $user_id )->destroy_all();
            $user->set_role( '' );
        }
    }

    /** A signed, non-authenticating cookie is only a UX hint for expired sessions. */
    private static function marker( $access_id, $user_id ) {
        $payload = absint( $access_id ) . '.' . absint( $user_id );
        return $payload . '.' . hash_hmac( 'sha256', get_current_blog_id() . '|' . site_url() . '|' . $payload, wp_salt( 'auth' ) );
    }

    private static function marker_options( $expires ) {
        $options = array(
            'expires' => $expires,
            'path' => defined( 'COOKIEPATH' ) ? COOKIEPATH : '/',
            'secure' => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        );
        if ( defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ) {
            $options['domain'] = COOKIE_DOMAIN;
        }
        return $options;
    }

    public static function clear_session_marker() {
        if ( ! headers_sent() ) {
            setcookie( 'amta_session_context', '', self::marker_options( time() - HOUR_IN_SECONDS ) );
        }
    }

    private static function set_session_marker( $access_id, $user_id ) {
        // Kept for up to a year so the expired/revoked session can show its status.
        // This cookie NEVER authenticates the visitor, and the database is checked.
        if ( ! headers_sent() ) {
            setcookie( 'amta_session_context', self::marker( $access_id, $user_id ), self::marker_options( time() + YEAR_IN_SECONDS ) );
        }
    }

    /** Return a signed context record, without granting any privileges. */
    private static function closed_session_context() {
        $cookie = isset( $_COOKIE['amta_session_context'] ) && is_string( $_COOKIE['amta_session_context'] ) ? sanitize_text_field( wp_unslash( $_COOKIE['amta_session_context'] ) ) : '';
        if ( ! preg_match( '/\A([1-9][0-9]*)\.([1-9][0-9]*)\.([a-f0-9]{64})\z/D', $cookie, $matches ) ) {
            return false;
        }
        $id = absint( $matches[1] );
        $user_id = absint( $matches[2] );
        if ( ! $id || ! $user_id || ! hash_equals( self::marker( $id, $user_id ), $cookie ) ) {
            return false;
        }
        if ( (int) get_user_meta( $user_id, 'amta_access_id', true ) !== $id ) {
            return false;
        }
        $record = AMTA_Storage::get_for_user( $user_id, $id );
        return $record ? $record : (object) array( 'status' => 'deleted' );
    }

    /** Limit probing and invitation replay requests without storing plain IP addresses. */
    private static function rate_limited() {
        $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : 'unknown';
        $key = 'amta_attempt_' . substr( hash_hmac( 'sha256', $ip, wp_salt( 'nonce' ) ), 0, 24 );
        $count = (int) get_transient( $key );
        if ( $count >= 30 ) {
            return true;
        }
        set_transient( $key, $count + 1, 15 * MINUTE_IN_SECONDS );
        return false;
    }

    /** Render and redeem links; the standard WordPress login form is not used for unavailable links. */
    public static function handle_invitation() {
        $method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
        // GET previews do not change state. POST confirms an invitation and must
        // pass the invitation-specific CSRF nonce before looking up the token.
        // Read only the invitation ID before the POST nonce check; it selects
        // the correct invitation-specific nonce and must not change any state.
        $has_id = 'POST' === $method ? isset( $_POST['amta_access'] ) : isset( $_GET['amta_access'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- ID presence is read-only; POST nonce verification follows before redeeming.
        $has_token = 'POST' === $method ? isset( $_POST['amta_token'] ) : isset( $_GET['amta_token'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Only checks presence; public GET invitation previews need no nonce.
        if ( ! $has_id && ! $has_token ) {
            // A WordPress auth_redirect after a previously redeemed invitation
            // ordinarily lands on wp-login.php. Display the closed-access page.
            $action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login';
            if ( 'GET' === $method && ( '' === $action || 'login' === $action ) ) {
                $closed = self::closed_session_context();
                if ( $closed ) {
                    self::error( __( 'Your temporary session is no longer available.', 'oneclicky-temporary-access' ), 410, self::closed_kind( $closed ) );
                }
            }
            return;
        }
        self::no_cache();
        if ( self::rate_limited() ) {
            self::error( __( 'Too many attempts. Please try again later.', 'oneclicky-temporary-access' ), 429, 'limited' );
        }
        // GET is a read-only preview that is reachable from a public invitation
        // link. POST must verify a nonce before reading token or changing state.
        $id_input = 'POST' === $method
            ? ( $has_id && is_scalar( $_POST['amta_access'] ) ? absint( wp_unslash( $_POST['amta_access'] ) ) : 0 ) // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Only used to construct the nonce checked immediately below.
            : ( $has_id && is_scalar( $_GET['amta_access'] ) ? absint( wp_unslash( $_GET['amta_access'] ) ) : 0 ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Public read-only GET invitation preview.
        $id = absint( $id_input );
        if ( ! $id ) {
            self::error( __( 'This access link is invalid or unavailable.', 'oneclicky-temporary-access' ), 403, 'invalid' );
        }
        if ( 'POST' === $method ) {
            $confirm_nonce = isset( $_POST['amta_confirm_nonce'] ) && is_scalar( $_POST['amta_confirm_nonce'] )
                ? sanitize_text_field( wp_unslash( $_POST['amta_confirm_nonce'] ) ) : '';
            if ( ! wp_verify_nonce( $confirm_nonce, 'amta_redeem_' . $id ) ) {
                self::error( __( 'The confirmation request could not be verified.', 'oneclicky-temporary-access' ), 403, 'invalid' );
            }
        }
        // Token is untrusted input: unslash, sanitize and validate its exact shape.
        $token_input = 'POST' === $method
            ? ( $has_token && is_scalar( $_POST['amta_token'] ) ? sanitize_text_field( wp_unslash( $_POST['amta_token'] ) ) : '' )
            : ( $has_token && is_scalar( $_GET['amta_token'] ) ? sanitize_text_field( wp_unslash( $_GET['amta_token'] ) ) : '' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only public invitation link; state change requires the verified POST nonce.
        $token = $token_input;
        if ( ! preg_match( '/\A[a-f0-9]{64}\z/D', $token ) ) {
            self::error( __( 'This access link is invalid or unavailable.', 'oneclicky-temporary-access' ), 403, 'invalid' );
        }
        if ( AMTA_Guard::locked() ) { self::error( __( 'Temporary access is disabled by the site owner.', 'oneclicky-temporary-access' ), 403, 'revoked' ); }
        $record = AMTA_Storage::get( $id );
        if ( ! $record && AMTA_Storage::is_deleted_token( $id, self::digest( $token ) ) ) {
            self::error( __( 'This invitation was permanently deleted.', 'oneclicky-temporary-access' ), 410, 'deleted' );
        }
        if ( ! $record || ! hash_equals( (string) $record->token_hash, self::digest( $token ) ) ) {
            self::error( __( 'This access link is invalid or unavailable.', 'oneclicky-temporary-access' ), 403, 'invalid' );
        }
        if ( ! AMTA_Storage::is_live( $record ) ) {
            if ( 'active' === $record->status ) {
                AMTA_Storage::close( $record->id, 'expired' );
            }
            self::error( __( 'This access link is no longer available.', 'oneclicky-temporary-access' ), 410, self::closed_kind( $record ) );
        }
        if ( (int) $record->uses >= (int) $record->max_uses ) {
            self::error( __( 'This invitation has reached its use limit.', 'oneclicky-temporary-access' ), 410, 'used' );
        }
        $user = get_userdata( (int) $record->user_id );
        if ( ! $user || (int) get_user_meta( $user->ID, 'amta_access_id', true ) !== (int) $record->id ) {
            self::error( __( 'This access link is invalid or unavailable.', 'oneclicky-temporary-access' ), 403, 'invalid' );
        }

        // GET is preview-only. A link scanner cannot consume an invitation.
        if ( 'POST' !== $method ) {
            self::show_confirmation( $record, $token );
        }
        if ( AMTA_OTP::required( $record ) ) {
            $otp = isset( $_POST['amta_otp_code'] ) && is_scalar( $_POST['amta_otp_code'] ) ? sanitize_text_field( wp_unslash( $_POST['amta_otp_code'] ) ) : '';
            if ( '' === $otp ) {
                if ( ! AMTA_OTP::send( $record ) ) { self::portal( 'otp_delivery', $record, $token, 503 ); }
                self::portal( 'otp', $record, $token, 200 );
            }
            if ( ! AMTA_OTP::verify( $record, $otp ) ) { self::portal( 'otp_failed', $record, $token, 403 ); }
        }
        if ( ! AMTA_Storage::redeem( $record, self::digest( $token ) ) ) {
            self::error( __( 'This invitation is no longer available.', 'oneclicky-temporary-access' ), 410, 'used' );
        }
        wp_clear_auth_cookie();
        wp_set_current_user( $user->ID );
        wp_set_auth_cookie( $user->ID, false, is_ssl() );
        self::set_session_marker( $record->id, $user->ID );
        // Core's wp_login action must retain its public name for WordPress interoperability.
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Intentionally firing the core wp_login action, not defining a new hook.
        do_action( 'wp_login', $user->user_login, $user );
        AMTA_Guard::alert( 'invitation_login', (int) $record->id );
        wp_safe_redirect( admin_url( 'index.php' ), 303 );
        exit;
    }

    private static function closed_kind( $record ) {
        if ( 'active' === $record->status && AMTA_Storage::is_live( $record ) ) {
            return 'session';
        }
        if ( 'deleted' === $record->status ) {
            return 'deleted';
        }
        if ( 'revoked' === $record->status ) {
            return 'revoked';
        }
        return 'expired';
    }

    private static function no_cache() {
        nocache_headers();
        header( 'Referrer-Policy: no-referrer', true );
        header( 'X-Robots-Tag: noindex, nofollow, noarchive', true );
        header( 'X-Content-Type-Options: nosniff', true );
        header( 'Content-Security-Policy: default-src \'none\'; style-src \'self\' \'unsafe-inline\'; script-src \'self\'; img-src \'self\' data:; form-action \'self\'; base-uri \'none\'; frame-ancestors \'none\'', true );
    }

    private static function error( $message, $status = 403, $kind = 'invalid' ) {
        self::portal( $kind, null, '', absint( $status ) );
    }

    private static function show_confirmation( $record, $token ) {
        self::portal( 'ready', $record, $token, 200 );
    }

    /** Shared stand-alone UX used for confirmations and all failed link/session states. */
    private static function portal( $kind, $record, $token, $http_status ) {
        self::no_cache();
        status_header( $http_status );
        $labels = array(
            'session' => array( __( 'Your sign-in session has ended', 'oneclicky-temporary-access' ), __( 'This browser is no longer signed in. Please request another invitation or use a valid unused invitation link.', 'oneclicky-temporary-access' ), __( 'Session unavailable', 'oneclicky-temporary-access' ) ),
            'otp' => array( __( 'Check your email for a code', 'oneclicky-temporary-access' ), __( 'Enter the eight-digit verification code sent to your invitation email. It expires in 10 minutes.', 'oneclicky-temporary-access' ), __( 'Email verification', 'oneclicky-temporary-access' ) ),
            'otp_failed' => array( __( 'Code incorrect or expired', 'oneclicky-temporary-access' ), __( 'Check your code. After five incorrect attempts you must request a new code.', 'oneclicky-temporary-access' ), __( 'Email verification', 'oneclicky-temporary-access' ) ),
            'otp_delivery' => array( __( 'Verification email unavailable', 'oneclicky-temporary-access' ), __( 'Your site could not send a code, or the send limit was reached. Contact the site owner or try again later.', 'oneclicky-temporary-access' ), __( 'Email delivery', 'oneclicky-temporary-access' ) ),
            'ready' => array( __( 'Your secure access is ready', 'oneclicky-temporary-access' ), __( 'Review your invitation, then continue securely to the dashboard.', 'oneclicky-temporary-access' ), __( 'Invitation verified', 'oneclicky-temporary-access' ) ),
            'expired' => array( __( 'Your access has expired', 'oneclicky-temporary-access' ), __( 'The allowed time for this invitation has ended. Request a fresh invitation from the site owner.', 'oneclicky-temporary-access' ), __( 'Access expired', 'oneclicky-temporary-access' ) ),
            'revoked' => array( __( 'This access was revoked', 'oneclicky-temporary-access' ), __( 'The site owner has disabled this temporary access. This invitation can no longer be used.', 'oneclicky-temporary-access' ), __( 'Access revoked', 'oneclicky-temporary-access' ) ),
            'deleted' => array( __( 'This invitation was deleted', 'oneclicky-temporary-access' ), __( 'This invitation has been removed by the site owner. Please request a new access link.', 'oneclicky-temporary-access' ), __( 'Access unavailable', 'oneclicky-temporary-access' ) ),
            'used' => array( __( 'This link has already been used', 'oneclicky-temporary-access' ), __( 'The invitation has reached its allowed login count. Ask the site owner for another invitation.', 'oneclicky-temporary-access' ), __( 'Limit reached', 'oneclicky-temporary-access' ) ),
            'limited' => array( __( 'Too many attempts', 'oneclicky-temporary-access' ), __( 'Please wait a few minutes before trying again.', 'oneclicky-temporary-access' ), __( 'Temporarily unavailable', 'oneclicky-temporary-access' ) ),
            'invalid' => array( __( 'This access link is unavailable', 'oneclicky-temporary-access' ), __( 'This invitation cannot be verified. Check that you received the full link or contact the site owner.', 'oneclicky-temporary-access' ), __( 'Invalid invitation', 'oneclicky-temporary-access' ) ),
        );
        $content = isset( $labels[ $kind ] ) ? $labels[ $kind ] : $labels['invalid'];
        $ready = in_array( $kind, array( 'ready', 'otp', 'otp_failed', 'otp_delivery' ), true ) && $record;
        if ( 'otp_delivery' === $kind ) {
            $otp_failure = AMTA_OTP::last_send_error();
            if ( in_array( $otp_failure, array( 'limit', 'attempts' ), true ) ) {
                $content[1] = __( 'Too many verification attempts. Wait 15 minutes, then try again, or ask the site owner for a new invitation.', 'oneclicky-temporary-access' );
            } elseif ( in_array( $otp_failure, array( 'cooldown', 'retry' ), true ) ) {
                $content[1] = __( 'Please wait about a minute before requesting another code. If email is not arriving, contact the site owner.', 'oneclicky-temporary-access' );
            } else {
                $content[1] = __( 'WordPress could not submit the verification email. Ask the site owner to configure GoSMTP and test delivery. Your access link is still valid and no OTP has been consumed.', 'oneclicky-temporary-access' );
            }
        }
        $pending_otp = $ready && AMTA_OTP::required( $record ) && AMTA_OTP::has_pending( $record );
        if ( 'otp_delivery' === $kind && $pending_otp ) {
            $content[1] .= ' ' . __( 'If you already received a valid code, you can still enter it below.', 'oneclicky-temporary-access' );
        }
        if ( 'ready' === $kind && AMTA_OTP::required( $record ) ) {
            $content[1] = __( 'Continue to receive an eight-digit verification code at the recipient email address. You must enter it before the dashboard opens.', 'oneclicky-temporary-access' );
        }
        $role_names = wp_roles()->get_names();
        $role = $ready ? AMTA_Hardening::role_label( $record->role, isset( $role_names[ $record->role ] ) ? translate_user_role( $role_names[ $record->role ] ) : $record->role ) : '';
        $expires = $ready ? wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $record->expires_at ) : '';
        wp_enqueue_style( 'amta-portal', AMTA_URL . 'assets/css/portal.css', array(), AMTA_VERSION );
        if ( 'revoked' === $kind ) {
            wp_enqueue_script( 'amta-portal-game', AMTA_URL . 'assets/js/portal-game.js', array(), AMTA_VERSION, false );
        }
        ?>
<!doctype html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php echo esc_attr( get_bloginfo( 'charset' ) ); ?>">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="robots" content="noindex,nofollow,noarchive">
    <meta name="referrer" content="no-referrer">
    <title><?php echo esc_html( $content[0] . ' · OneClicky' ); ?></title>
    <?php wp_print_styles( 'amta-portal' ); ?>
</head>
<body class="amta-portal amta-portal-<?php echo esc_attr( $kind ); ?>">
<div class="amta-backdrop" aria-hidden="true"></div>
<main class="amta-portal-card">
    <div class="amta-brand"><span class="amta-brand-symbol" aria-hidden="true">&#10003;</span><span>OneClicky</span><span class="amta-brand-pill"><?php esc_html_e( 'SECURE ACCESS', 'oneclicky-temporary-access' ); ?></span></div>
    <div class="amta-portal-top"><div class="amta-portal-icon" aria-hidden="true"><?php echo $ready ? '&#10003;' : '&#8722;'; ?></div><span class="amta-portal-eyebrow"><?php echo esc_html( $content[2] ); ?></span><h1><?php echo esc_html( $content[0] ); ?></h1><p><?php echo esc_html( $content[1] ); ?></p></div>
    <?php if ( $ready ) : ?>
        <div class="amta-invite-details" aria-label="<?php esc_attr_e( 'Invitation details', 'oneclicky-temporary-access' ); ?>">
            <div><span><?php esc_html_e( 'Invited recipient', 'oneclicky-temporary-access' ); ?></span><strong><?php echo esc_html( $record->label ); ?></strong></div>
            <div><span><?php esc_html_e( 'Access level', 'oneclicky-temporary-access' ); ?></span><strong><?php echo esc_html( $role ); ?></strong></div>
            <div><span><?php esc_html_e( 'Valid until', 'oneclicky-temporary-access' ); ?></span><strong><?php echo esc_html( $expires ); ?></strong></div>
        </div>
        <form method="post" action="<?php echo esc_url( wp_login_url() ); ?>">
            <input type="hidden" name="amta_access" value="<?php echo esc_attr( (string) $record->id ); ?>">
            <input type="hidden" name="amta_token" value="<?php echo esc_attr( $token ); ?>">
            <?php wp_nonce_field( 'amta_redeem_' . $record->id, 'amta_confirm_nonce', false ); ?>
            <?php if ( ( in_array( $kind, array( 'otp', 'otp_failed' ), true ) || ( 'otp_delivery' === $kind && $pending_otp ) ) ) : ?>
                <label class="amta-otp-label" for="amta-otp-code"><?php esc_html_e( 'Email verification code', 'oneclicky-temporary-access' ); ?></label>
                <input class="amta-otp-input" id="amta-otp-code" name="amta_otp_code" inputmode="numeric" pattern="[0-9]{8}" maxlength="8" autocomplete="one-time-code" required placeholder="12345678">
            <?php endif; ?>
            <button class="amta-portal-button" type="submit"><?php echo ( in_array( $kind, array( 'otp', 'otp_failed' ), true ) || ( 'otp_delivery' === $kind && $pending_otp ) ) ? esc_html__( 'Verify code and sign in', 'oneclicky-temporary-access' ) : ( 'otp_delivery' === $kind ? esc_html__( 'Try sending code again', 'oneclicky-temporary-access' ) : ( AMTA_OTP::required( $record ) ? esc_html__( 'Send verification code', 'oneclicky-temporary-access' ) : esc_html__( 'Continue securely to dashboard', 'oneclicky-temporary-access' ) ) ); ?><span aria-hidden="true">&#8594;</span></button>
        </form>
        <?php if ( ( in_array( $kind, array( 'otp', 'otp_failed' ), true ) || ( 'otp_delivery' === $kind && $pending_otp ) ) ) : ?>
            <form method="post" action="<?php echo esc_url( wp_login_url() ); ?>" class="amta-otp-resend-form">
                <input type="hidden" name="amta_access" value="<?php echo esc_attr( (string) $record->id ); ?>">
                <input type="hidden" name="amta_token" value="<?php echo esc_attr( $token ); ?>">
                <?php wp_nonce_field( 'amta_redeem_' . $record->id, 'amta_confirm_nonce', false ); ?>
                <button class="amta-otp-resend-button" type="submit"><?php esc_html_e( 'Resend a new verification code', 'oneclicky-temporary-access' ); ?></button>
            </form>
            <p class="amta-security-caption"><?php esc_html_e( 'Up to three accepted sends every fifteen minutes, with a short resend wait. Check your Spam folder. Codes expire after ten minutes.', 'oneclicky-temporary-access' ); ?></p>
        <?php else : ?>
            <p class="amta-security-caption"><?php esc_html_e( 'The invitation is used only when you continue. Never share this secure link publicly.', 'oneclicky-temporary-access' ); ?></p>
        <?php endif; ?>
    <?php else : ?>
        <div class="amta-state-panel"><span class="amta-state-dot" aria-hidden="true"></span><div><strong><?php esc_html_e( 'Sign-in is no longer possible with this link', 'oneclicky-temporary-access' ); ?></strong><span><?php esc_html_e( 'No password or WordPress login is required to check this status.', 'oneclicky-temporary-access' ); ?></span></div></div>
        <p class="amta-security-caption"><?php esc_html_e( 'For a new invitation, contact the person who granted your temporary access.', 'oneclicky-temporary-access' ); ?></p>
    <?php endif; ?>
    <?php if ( 'revoked' === $kind ) : ?>
        <section class="amta-runner" aria-labelledby="amta-runner-title">
            <div class="amta-runner-head"><div class="amta-runner-mark" aria-hidden="true">&#9654;</div><div><h2 id="amta-runner-title"><?php esc_html_e( 'Mint Runner · Dino-style jump game', 'oneclicky-temporary-access' ); ?></h2><p><?php esc_html_e( 'A little offline dinosaur runner, inspired by the classic browser game. Jump over obstacles to score points.', 'oneclicky-temporary-access' ); ?></p></div></div>
            <div class="amta-runner-stats"><span><?php esc_html_e( 'Score', 'oneclicky-temporary-access' ); ?> <strong id="amta-runner-score">00000</strong></span><span><?php esc_html_e( 'Best this visit', 'oneclicky-temporary-access' ); ?> <strong id="amta-runner-best">00000</strong></span></div>
            <canvas class="amta-runner-canvas" id="amta-runner-canvas" width="640" height="220" tabindex="0" role="img" aria-label="<?php esc_attr_e( 'Dinosaur-style runner. Press Space, Up Arrow, or tap to jump over obstacles.', 'oneclicky-temporary-access' ); ?>"></canvas>
            <div class="amta-runner-controls"><button class="amta-runner-start" id="amta-runner-start" type="button"><?php esc_html_e( 'Start running', 'oneclicky-temporary-access' ); ?></button><button class="amta-runner-jump" id="amta-runner-jump" type="button"><?php esc_html_e( 'Jump', 'oneclicky-temporary-access' ); ?> <span aria-hidden="true">&#8593;</span></button></div>
            <p class="amta-runner-message" id="amta-runner-message" role="status"><?php esc_html_e( 'Tap the game or Jump button on mobile; Space / Up Arrow on desktop. No tracking, no saved scores.', 'oneclicky-temporary-access' ); ?></p>
        </section>
    <?php endif; ?>
    <footer class="amta-portal-footer"><span><?php esc_html_e( 'Protected by OneClicky', 'oneclicky-temporary-access' ); ?></span><span aria-hidden="true">&bull;</span><span><?php esc_html_e( 'Private · Time-limited · Revocable', 'oneclicky-temporary-access' ); ?></span></footer>
</main>
<?php if ( 'revoked' === $kind ) { wp_print_scripts( 'amta-portal-game' ); } ?>
</body></html>
        <?php
        exit;
    }
}
