<?php
/** Optional, fail-closed email ownership challenge before invitation redemption. */
if ( ! defined( 'ABSPATH' ) ) { exit; }
final class AMTA_OTP {
    private static function key( $id ) { return 'amta_otp_v113_' . absint( $id ); }

    public static function required( $record ) {
        return $record && '1' === (string) get_user_meta( (int) $record->user_id, 'amta_require_otp', true );
    }

    public static function clear( $id ) { delete_transient( self::key( $id ) ); }

    private static $send_error = 'unknown';

    public static function last_send_error() { return self::$send_error; }

    /** The real recipient email is private metadata, not the synthetic WP email. */
    public static function send( $record ) {
        self::$send_error = 'unavailable';
        if ( ! AMTA_Storage::is_live( $record ) || ! self::required( $record ) ) { return false; }
        $id = (int) $record->id;
        if ( (int) get_transient( 'amta_otp_fails_' . $id ) >= 5 ) { self::$send_error = 'attempts'; return false; }
        if ( (int) get_transient( 'amta_otp_sends_' . $id ) >= 3 ) { self::$send_error = 'limit'; return false; }
        if ( get_transient( 'amta_otp_cooldown_' . $id ) ) { self::$send_error = 'cooldown'; return false; }
        if ( get_transient( 'amta_otp_failure_backoff_' . $id ) ) { self::$send_error = 'retry'; return false; }
        $email = get_user_meta( (int) $record->user_id, 'amta_recipient_email', true );
        if ( ! is_email( $email ) ) { self::$send_error = 'address'; return false; }
        try { $code = str_pad( (string) random_int( 0, 99999999 ), 8, '0', STR_PAD_LEFT ); }
        catch ( Exception $e ) { self::$send_error = 'random'; return false; }
        // Preserve a previously issued valid code when email transport fails.
        $data = array( 'hash' => hash_hmac( 'sha256', $code, wp_salt( 'auth' ) ), 'token_hash' => (string) $record->token_hash, 'attempts' => 0, 'expires_at' => time() + 10 * MINUTE_IN_SECONDS );
        $sent = wp_mail( $email, '[OneClicky] Your one-time verification code', "Your OneClicky verification code is: {$code}\n\nIt expires in 10 minutes. Do not share it.\nIf you did not request this, contact the site owner.", array( 'Content-Type: text/plain; charset=UTF-8' ) );
        if ( ! $sent ) {
            self::$send_error = 'transport';
            set_transient( 'amta_otp_failure_backoff_' . $id, 1, 30 );
            return false;
        }
        set_transient( self::key( $id ), $data, 10 * MINUTE_IN_SECONDS );
        set_transient( 'amta_otp_sends_' . $id, (int) get_transient( 'amta_otp_sends_' . $id ) + 1, 15 * MINUTE_IN_SECONDS );
        set_transient( 'amta_otp_cooldown_' . $id, 1, 45 );
        self::$send_error = '';
        return true;
    }

    public static function has_pending( $record ) {
        if ( ! $record ) { return false; }
        $data = get_transient( self::key( $record->id ) );
        return is_array( $data ) && isset( $data['token_hash'], $data['expires_at'] ) &&
            (int) $data['expires_at'] >= time() && hash_equals( (string) $record->token_hash, (string) $data['token_hash'] );
    }

    public static function verify( $record, $candidate ) {
        $data = get_transient( self::key( $record->id ) );
        if ( ! is_array( $data ) || ! isset( $data['hash'], $data['attempts'], $data['token_hash'], $data['expires_at'] ) || ! hash_equals( (string) $record->token_hash, (string) $data['token_hash'] ) ) { return false; }
        if ( (int) $data['expires_at'] < time() ) { self::clear( $record->id ); return false; }
        if ( (int) $data['attempts'] >= 5 || (int) get_transient( 'amta_otp_fails_' . (int) $record->id ) >= 5 ) { return false; }
        $valid = is_string( $candidate ) && preg_match( '/\A[0-9]{8}\z/D', $candidate ) && hash_equals( (string) $data['hash'], hash_hmac( 'sha256', $candidate, wp_salt( 'auth' ) ) );
        if ( $valid ) { self::clear( $record->id ); delete_transient( 'amta_otp_fails_' . (int) $record->id ); return true; }
        $data['attempts'] = (int) $data['attempts'] + 1;
        $failed_total = (int) get_transient( 'amta_otp_fails_' . (int) $record->id ) + 1;
        set_transient( 'amta_otp_fails_' . (int) $record->id, $failed_total, 15 * MINUTE_IN_SECONDS );
        set_transient( self::key( $record->id ), $data, max( 1, (int) $data['expires_at'] - time() ) );
        if ( $failed_total >= 5 ) { AMTA_Guard::alert( 'otp_failures', (int) $record->id ); }
        return false;
    }
}
