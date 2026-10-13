<?php
/** Build distinct invitation accounts, even when recipient emails are already registered. */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class AMTA_Creator {
    /**
     * WordPress requires each users.user_email to be unique. Recipient email is
     * deliberately a separate, private metadata value: NEVER give a temporary
     * account the original user's email or grant access to an existing account.
     */
    public static function validate_recipient( $name, $email ) {
        if ( ! is_string( $name ) || ! is_string( $email ) ) {
            return new WP_Error( 'amta_invalid_recipient', __( 'Enter a name and a valid email address.', 'oneclicky-temporary-access' ) );
        }
        $name = trim( sanitize_text_field( $name ) );
        $name = function_exists( 'mb_substr' ) ? mb_substr( $name, 0, 100 ) : substr( $name, 0, 100 );
        $email = trim( $email );
        if ( '' === $name ) {
            return new WP_Error( 'amta_missing_name', __( 'Recipient name is required.', 'oneclicky-temporary-access' ) );
        }
        if ( '' === $email || strlen( $email ) > 254 || ! is_email( $email ) ) {
            return new WP_Error( 'amta_missing_email', __( 'Enter a valid email address. Email is required.', 'oneclicky-temporary-access' ) );
        }
        $email = sanitize_email( $email );
        if ( ! is_email( $email ) ) {
            return new WP_Error( 'amta_invalid_email', __( 'Enter a valid email address.', 'oneclicky-temporary-access' ) );
        }
        return array( 'name' => $name, 'email' => $email );
    }

    /** Parse up to twenty "Name,email@example.com" entries. No rows are created on invalid input. */
    public static function parse_bulk( $raw ) {
        if ( ! is_string( $raw ) || strlen( $raw ) > 10000 ) {
            return new WP_Error( 'amta_bulk_length', __( 'Bulk input is too long (maximum 20 recipients).', 'oneclicky-temporary-access' ) );
        }
        $lines = preg_split( '/\r\n|\n|\r/', $raw );
        $recipients = array();
        foreach ( $lines as $index => $line ) {
            if ( '' === trim( $line ) ) {
                continue;
            }
            if ( count( $recipients ) >= 20 ) {
                return new WP_Error( 'amta_bulk_max', __( 'You can create up to 20 accounts per batch.', 'oneclicky-temporary-access' ) );
            }
            $parts = str_getcsv( $line );
            if ( 2 !== count( $parts ) ) {
                return new WP_Error( 'amta_bulk_format', sprintf( /* translators: %d: line number */ __( 'Line %d must contain a name and email, separated by a comma.', 'oneclicky-temporary-access' ), $index + 1 ) );
            }
            $recipient = self::validate_recipient( $parts[0], $parts[1] );
            if ( is_wp_error( $recipient ) ) {
                return new WP_Error( 'amta_bulk_invalid', sprintf( /* translators: 1: line number; 2: reason */ __( 'Line %1$d: %2$s', 'oneclicky-temporary-access' ), $index + 1, $recipient->get_error_message() ) );
            }
            $recipients[] = $recipient;
        }
        if ( ! $recipients ) {
            return new WP_Error( 'amta_bulk_empty', __( 'Add at least one recipient, one per line.', 'oneclicky-temporary-access' ) );
        }
        return $recipients;
    }

    /** Create one *dedicated* WordPress user and one OneClicky invitation. */
    public static function create( $recipient, $role, $expires_at, $max_uses, $otp_required = false ) {
        $verified = self::validate_recipient( $recipient['name'], $recipient['email'] );
        if ( is_wp_error( $verified ) ) {
            return $verified;
        }
        try {
            $token = bin2hex( random_bytes( 32 ) );
            $username = 'amta_' . bin2hex( random_bytes( 12 ) );
        } catch ( Exception $e ) {
            return new WP_Error( 'amta_random_failed', __( 'Secure token generation failed. Please retry.', 'oneclicky-temporary-access' ) );
        }

        // Unique non-deliverable address avoids WordPress's email uniqueness
        // restriction. Original recipient email is recorded in usermeta instead.
        $user_id = wp_insert_user(
            array(
                'user_login' => $username,
                'user_pass' => wp_generate_password( 48, true, true ),
                'user_email' => $username . '@example.invalid',
                'display_name' => $verified['name'],
                'nickname' => $verified['name'],
                'role' => AMTA_Hardening::safe_role( $role ),
            )
        );
        if ( is_wp_error( $user_id ) ) {
            return $user_id;
        }

        $access_id = AMTA_Storage::create( $user_id, get_current_user_id(), $verified['name'], $role, AMTA_Security::digest( $token ), $max_uses, $expires_at );
        if ( ! $access_id ) {
            self::delete_new_user( $user_id );
            return new WP_Error( 'amta_save_failed', __( 'Could not save the invitation. The unused temporary user was removed.', 'oneclicky-temporary-access' ) );
        }
        if ( ! update_user_meta( $user_id, 'amta_access_id', $access_id ) ) {
            // Marker could not be saved: remove privileges immediately, regardless
            // of whether the matching record can be marked as closed.
            $user = get_userdata( $user_id );
            if ( $user ) {
                $user->set_role( '' );
            }
            WP_Session_Tokens::get_instance( $user_id )->destroy_all();
            AMTA_Storage::close( $access_id, 'revoked', get_current_user_id() );
            self::delete_new_user( $user_id );
            return new WP_Error( 'amta_security_failed', __( 'The temporary user could not be secured. Please retry.', 'oneclicky-temporary-access' ) );
        }
        if ( ! update_user_meta( $user_id, 'amta_recipient_email', $verified['email'] ) ) {
            AMTA_Storage::close( $access_id, 'revoked', get_current_user_id() );
            self::delete_new_user( $user_id );
            return new WP_Error( 'amta_email_save_failed', __( 'The recipient email could not be saved. Please retry.', 'oneclicky-temporary-access' ) );
        }
        if ( $otp_required && ! update_user_meta( $user_id, 'amta_require_otp', '1' ) ) {
            AMTA_Storage::close( $access_id, 'revoked', get_current_user_id() );
            self::delete_new_user( $user_id );
            return new WP_Error( 'amta_otp_save_failed', __( 'Email verification could not be secured for this invitation.', 'oneclicky-temporary-access' ) );
        }
        // Encrypt the token at rest so owners can copy it after refreshing.
        if ( ! AMTA_Vault::save( $access_id, $token ) ) {
            AMTA_Storage::close( $access_id, 'revoked', get_current_user_id() );
            self::delete_new_user( $user_id );
            return new WP_Error( 'amta_secret_store_failed', __( 'Secure link encryption is unavailable. The invitation was cancelled; check PHP OpenSSL or Sodium.', 'oneclicky-temporary-access' ) );
        }
        return array(
            'id' => $access_id,
            'name' => $verified['name'],
            'email' => $verified['email'],
            'url' => add_query_arg( array( 'amta_access' => $access_id, 'amta_token' => $token ), wp_login_url() ),
        );
    }

    private static function delete_new_user( $user_id ) {
        require_once ABSPATH . 'wp-admin/includes/user.php';
        wp_delete_user( $user_id );
    }

    /** Emailing is an opt-in convenience, not proof of delivery or identity. */
    public static function email_invitation( $invitation ) {
        $site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
        $subject = sprintf( /* translators: %s: site name */ __( '[%s] Your temporary access link', 'oneclicky-temporary-access' ), $site );
        $body = sprintf(
            /* translators: 1: recipient name; 2: website title; 3: invitation URL */
            __( "Hello %1\$s,\n\nYou have been invited to access %2\$s temporarily.\n\nSecure sign-in link:\n%3\$s\n\nOpen the link, then confirm your login. The link expires automatically and can be revoked early. Please do not forward it.\n\nIf you did not expect this invitation, ignore this message.", 'oneclicky-temporary-access' ),
            $invitation['name'],
            $site,
            $invitation['url']
        );
        return (bool) wp_mail( $invitation['email'], $subject, $body, array( 'Content-Type: text/plain; charset=UTF-8' ) );
    }
}
