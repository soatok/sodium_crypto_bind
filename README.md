# crypto_bind

First there was `crypto_box()`, which facilitated authenticated public-key
encryption using curve25519 and xsalsa20poly1305, which both the sender and
recipient can decrypt.

Then there came `crypto_box_seal()`, which facilitated **anonymous** public-key
encryption using curve25519 and xsalsa20poly1305, which only the recipient
can decrypt.

Our Contribution: Authenticated public-key encryption that only the
recipient can decrypt.

## API

### sodium_crypto_bind()

Returns a `string`.

**Arguments**:

1. The plaintext message
2. The sender's curve25519 secret key.
3. The recipient's curve25519 public key.

### sodium_crypto_bind_open()

Returns a `string`.

**Arguments**:

1. The bound mesage
2. The sender's curve25519 public key.
3. The recipient's curve25519 secret key.

## Cryptographic Algorithms Used

* X25519 (ECDH over Curve25519)
* BLAKE2b
* XChaCha20-Poly1305




