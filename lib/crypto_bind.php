<?php
declare(strict_types=1);

/**
 * @param string $message
 * @param string $senderSK
 * @param string $recipientPK
 * @return string
 * @throws SodiumException
 */
function sodium_crypto_bind(string $message, string $senderSK, string $recipientPK): string
{
    $skLen = mb_strlen($senderSK, '8bit');
    if ($skLen === 32) {
    } elseif ($skLen === 64) {
        $senderSK = mb_substr($senderSK, 0, 32, '8bit');
    } else {
        throw new \SodiumException('Invalid secret key size');
    }

    $ephemeral = sodium_crypto_box_keypair();
    $eph_sk = sodium_crypto_box_secretkey($ephemeral);
    $eph_pk = sodium_crypto_box_publickey($ephemeral);
    sodium_memzero($ephemeral);

    $xx1 = sodium_crypto_scalarmult($eph_sk, $recipientPK);
    $xx2 = sodium_crypto_scalarmult($senderSK, $recipientPK);
    $key = sodium_crypto_generichash($xx1 . $xx2);
    $nonce = sodium_crypto_generichash($eph_pk . $recipientPK, '', 24);
    sodium_memzero($eph_sk);
    sodium_memzero($xx1);
    sodium_memzero($xx2);

    $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
        $message,
        $eph_pk,
        $nonce,
        $key
    );
    sodium_memzero($message);
    sodium_memzero($nonce);
    sodium_memzero($key);
    return $eph_pk . $ciphertext;
}

/**
 * @param string $message
 * @param string $senderPK
 * @param string $recipientSK
 * @return string
 * @throws SodiumException
 */
function sodium_crypto_bind_open(string $message, string $senderPK, string $recipientSK): string
{
    $skLen = mb_strlen($recipientSK, '8bit');
    if ($skLen === 32) {
        $recipientPK = sodium_crypto_box_publickey_from_secretkey($recipientSK);
    } elseif ($skLen === 64) {
        $recipientPK = mb_substr($recipientSK, 32, 32, '8bit');
        $recipientSK = mb_substr($recipientSK, 0, 32, '8bit');
    } else {
        throw new \SodiumException('Invalid secret key size');
    }
    $eph_pk = mb_substr($message, 0, 32, '8bit');
    $cipher = mb_substr($message, 32, null, '8bit');

    $xx1 = sodium_crypto_scalarmult($recipientSK, $eph_pk);
    $xx2 = sodium_crypto_scalarmult($recipientSK, $senderPK);
    $key = sodium_crypto_generichash($xx1 . $xx2);
    $nonce = sodium_crypto_generichash($eph_pk . $recipientPK, '', 24);
    sodium_memzero($xx1);
    sodium_memzero($xx2);

    /** @var string|bool $plaintext */
    $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
        $cipher,
        $eph_pk,
        $nonce,
        $key
    );
    if (!is_string($plaintext)) {
        throw new \SodiumException('Invalid key');
    }
    sodium_memzero($message);
    sodium_memzero($nonce);
    sodium_memzero($key);
    return $plaintext;
}
