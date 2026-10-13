<?php
/** Encrypted, owner-only retrieval of unredeemed temporary invitation tokens. */
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class AMTA_Vault {
    private static function key() {
        // Stable until the WordPress authentication salts rotate.
        return hash( 'sha256', wp_salt( 'auth' ) . '|' . wp_salt( 'secure_auth' ), true );
    }

    public static function encrypt( $token ) {
        if ( ! is_string( $token ) || ! preg_match( '/\A[a-f0-9]{64}\z/D', $token ) ) { return false; }
        try {
            $key = self::key();
            if ( function_exists( 'sodium_crypto_secretbox' ) ) {
                $nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
                return 's1:' . base64_encode( $nonce . sodium_crypto_secretbox( $token, $nonce, $key ) );
            }
            if ( function_exists( 'openssl_encrypt' ) ) {
                $nonce = random_bytes( 12 );
                $tag = '';
                $cipher = openssl_encrypt( $token, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag );
                if ( false !== $cipher && strlen( $tag ) === 16 ) {
                    return 'g1:' . base64_encode( $nonce . $tag . $cipher );
                }
            }
        } catch ( Exception $e ) { return false; }
        return false; // Never persist plaintext or weakly encrypted tokens.
    }

    public static function decrypt( $stored ) {
        if ( ! is_string( $stored ) || strlen( $stored ) > 1000 ) { return false; }
        $key = self::key();
        $kind = substr( $stored, 0, 3 );
        $raw = base64_decode( substr( $stored, 3 ), true );
        if ( false === $raw ) { return false; }
        try {
            if ( 's1:' === $kind && function_exists( 'sodium_crypto_secretbox_open' ) && strlen( $raw ) > SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
                $n = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
                $token = sodium_crypto_secretbox_open( substr( $raw, $n ), substr( $raw, 0, $n ), $key );
            } elseif ( 'g1:' === $kind && function_exists( 'openssl_decrypt' ) && strlen( $raw ) > 28 ) {
                $token = openssl_decrypt( substr( $raw, 28 ), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr( $raw, 0, 12 ), substr( $raw, 12, 16 ) );
            } else { return false; }
        } catch ( Exception $e ) { return false; }
        return is_string( $token ) && preg_match( '/\A[a-f0-9]{64}\z/D', $token ) ? $token : false;
    }

    public static function save( $id, $token ) {
        global $wpdb;
        $secret = self::encrypt( $token );
        if ( false === $secret ) { return false; }
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic mutation of OneClicky custom tables; core metadata APIs cannot guarantee this transition.
        $changed = $wpdb->update(
            AMTA_Storage::table(), array( 'secret_enc' => $secret ),
            array( 'id' => absint( $id ), 'token_hash' => AMTA_Security::digest( $token ), 'status' => 'active' ),
            array( '%s' ), array( '%d', '%s', '%s' )
        );
        return 1 === $changed;
    }

    /** Returns false for closed, expired, used-up or previous-version invitations. */
    public static function link( $record ) {
        if ( ! AMTA_Guard::owner() || ! AMTA_Storage::is_live( $record ) ||
             (int) $record->uses >= (int) $record->max_uses || empty( $record->secret_enc ) ) { return false; }
        $token = self::decrypt( (string) $record->secret_enc );
        if ( false === $token || ! hash_equals( (string) $record->token_hash, AMTA_Security::digest( $token ) ) ) { return false; }
        return add_query_arg( array( 'amta_access' => (int) $record->id, 'amta_token' => $token ), wp_login_url() );
    }
}
