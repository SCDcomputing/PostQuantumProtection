"""Kyber-style key encapsulation: an ML-KEM-inspired key encapsulation
mechanism (KEM) demonstration.

EDUCATIONAL DEMONSTRATION ONLY - NOT production-grade cryptography.
This module is a small, readable teaching example of how a lattice-based
key encapsulation mechanism works - the same shape as ML-KEM (Kyber,
FIPS 203), the standardized post-quantum KEM. It uses tiny toy
parameters (secret dimension 16, modulus 257) that are trivially
breakable, has no protection against side-channel or chosen-ciphertext
attacks, and must NEVER be used to protect real data.

Real systems use the standardized ML-KEM (FIPS 203) with much larger
parameters (module dimension 2-4, ring degree 256, modulus 3329),
rejection sampling, the number-theoretic transform, and a vetted
implementation. If you need quantum-resistant encryption in production,
use a vetted library that implements ML-KEM - do not adapt this demo.

How it works (following the shape of ML-KEM / Kyber):
  - Key generation: pick a random secret vector s and random small
    errors e. The public key is a random matrix A and a vector
    b = A*s + e (mod q); the secret key is s, plus a random rejection
    seed z and a copy of the public key (ML-KEM's decapsulation key
    also carries the encryption key, so it can re-encrypt during
    decapsulation).
  - Encapsulation: pick a random 16-byte message m, encrypt it under
    the public key with the LWE public-key encryption from
    LatticeCrypto.py (one bit per ciphertext, shifted by half the
    modulus for a 1 bit), and derive the shared secret as
    SHA-256(m). The encryption randomness is derived from m itself,
    the way Kyber derives it with a hash - so the same message always
    encrypts the same way.
  - Decapsulation: decrypt the ciphertext back to m, re-encrypt m
    with the same derived randomness, and compare. If the
    re-encryption matches the ciphertext that was received, return
    SHA-256(m) - the same shared secret encapsulation produced. If it
    does not match (the ciphertext was tampered with, or the wrong
    key was used), return an unrelated pseudorandom value derived
    from the secret rejection seed z instead - this is Kyber's
    implicit rejection, and it means a tampered ciphertext fails
    cleanly instead of leaking anything about the secret key.

The demo parameters are chosen so decryption is reliable: every error
is -1, 0, or 1 and at most 32 of them are ever added together, so the
total noise is at most 32 - well under a quarter of the modulus
(257 / 4 is about 64).
"""

import hashlib
import random
import secrets

# --- Demo parameters (toy-sized; NOT secure, see the warning above) ---
SECRET_DIMENSION = 16   # length of the secret vector s (n)
NUM_SAMPLES = 32        # number of rows in the public key (m)
MODULUS = 257           # prime modulus (q); all arithmetic is mod 257
ERROR_BOUND = 1         # each error is drawn uniformly from {-1, 0, 1}
HALF_MODULUS = MODULUS // 2   # 128: the shift that encodes a 1 bit
MESSAGE_BYTES = 16     # the encapsulated message is 16 random bytes
SHARED_SECRET_BYTES = 32  # SHA-256 output


class _SecretsRNG:
    """Minimal random interface backed by the secrets module.

    Used when no random generator is supplied, so key generation and
    encapsulation use operating-system randomness by default. Tests
    pass a seeded random.Random instead, for determinism.
    """

    @staticmethod
    def randrange(stop):
        return secrets.randbelow(stop)

    @staticmethod
    def randbytes(n):
        return secrets.token_bytes(n)


def _sample_error(rng):
    """Return a small error, uniformly drawn from {-1, 0, 1}."""
    return rng.randrange(2 * ERROR_BOUND + 1) - ERROR_BOUND


def generate_keypair(rng=None):
    """Generate an ML-KEM-style keypair.

    Args:
        rng: an object with randrange(stop) and randbytes(n) methods
            (for example random.Random for seeded, deterministic runs).
            Defaults to operating-system randomness via secrets.

    Returns:
        (public_key, secret_key) where the public key is (A, b): A is
        a list of NUM_SAMPLES rows, each a list of SECRET_DIMENSION
        values in Z_q, and b is a list of NUM_SAMPLES values in Z_q
        with b = A*s + e (mod q). The secret key is
        (s, z, public_key): s is the secret vector, z is a random
        32-byte rejection seed used for implicit rejection, and the
        public key is carried along so decapsulation can re-encrypt.
    """
    rng = rng or _SecretsRNG()
    secret_vector = [rng.randrange(MODULUS) for _ in range(SECRET_DIMENSION)]
    matrix = [
        [rng.randrange(MODULUS) for _ in range(SECRET_DIMENSION)]
        for _ in range(NUM_SAMPLES)
    ]
    errors = [_sample_error(rng) for _ in range(NUM_SAMPLES)]
    public_vector = [
        (sum(a * s for a, s in zip(row, secret_vector)) + e) % MODULUS
        for row, e in zip(matrix, errors)
    ]
    public_key = (matrix, public_vector)
    rejection_seed = rng.randbytes(SHARED_SECRET_BYTES)
    return public_key, (secret_vector, rejection_seed, public_key)


def _bytes_to_bits(data):
    """Encode bytes as a list of bits (most significant first)."""
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bits_to_bytes(bits):
    """Decode a list of bits back to bytes."""
    byte_values = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        byte_values.append(byte)
    return bytes(byte_values)


def _encryption_rng(message):
    """Derive the encryption randomness from the message itself.

    Kyber derives its encryption randomness by hashing the message;
    that makes encryption deterministic for a given message, which is
    what lets decapsulation re-encrypt and check the ciphertext.
    """
    seed = hashlib.sha256(message).digest()
    return random.Random(int.from_bytes(seed[:8], "big"))


def _encrypt_bits(public_key, bits, rng):
    """Encrypt a list of bits under the public key.

    Returns a list of per-bit ciphertexts (u, v): u is a list of
    SECRET_DIMENSION values in Z_q and v is a single value in Z_q.
    The rng supplies the random subset of public-key rows summed for
    each bit; pass the rng from _encryption_rng for deterministic
    encryption, or any other rng for fresh randomness.
    """
    matrix, public_vector = public_key
    ciphertexts = []
    for bit in bits:
        subset = [rng.randrange(2) for _ in range(NUM_SAMPLES)]
        u = [
            sum(r * row[j] for r, row in zip(subset, matrix)) % MODULUS
            for j in range(SECRET_DIMENSION)
        ]
        v = (
            sum(r * b for r, b in zip(subset, public_vector))
            + bit * HALF_MODULUS
        ) % MODULUS
        ciphertexts.append((u, v))
    return ciphertexts


def _decrypt_bits(secret_vector, ciphertexts):
    """Decrypt a list of per-bit ciphertexts back to a list of bits."""
    bits = []
    for u, v in ciphertexts:
        noise = (v - sum(a * s for a, s in zip(u, secret_vector))) % MODULUS
        # noise is near 0 for a 0 bit and near HALF_MODULUS for a 1 bit;
        # the midpoint between them is a quarter of the modulus.
        if MODULUS // 4 <= noise < 3 * MODULUS // 4:
            bits.append(1)
        else:
            bits.append(0)
    return bits


def encaps(public_key, rng=None):
    """Encapsulate a shared secret under the public key.

    Args:
        rng: an object with randbytes(n) (for example random.Random
            for seeded, deterministic runs). Defaults to
            operating-system randomness via secrets.

    Returns:
        (ciphertext, shared_secret) where ciphertext is a list of
        per-bit ciphertexts and shared_secret is a 32-byte value
        (SHA-256 of the random encapsulated message). Send the
        ciphertext to the holder of the secret key; both sides end up
        with the same shared secret.
    """
    rng = rng or _SecretsRNG()
    message = rng.randbytes(MESSAGE_BYTES)
    ciphertext = _encrypt_bits(
        public_key, _bytes_to_bits(message), _encryption_rng(message)
    )
    shared_secret = hashlib.sha256(message).digest()
    return ciphertext, shared_secret


def decaps(secret_key, ciphertext):
    """Decapsulate a ciphertext with the secret key.

    Returns the 32-byte shared secret. If the ciphertext is exactly
    the one encapsulation produced, this is the same shared secret
    encapsulation returned. If the ciphertext was tampered with, or a
    different key is used, an unrelated pseudorandom value is
    returned instead (implicit rejection) - the call still succeeds,
    it just does not return the real secret.
    """
    secret_vector, rejection_seed, public_key = secret_key
    message = _bits_to_bytes(_decrypt_bits(secret_vector, ciphertext))
    re_encrypted = _encrypt_bits(
        public_key, _bytes_to_bits(message), _encryption_rng(message)
    )
    if re_encrypted == ciphertext:
        return hashlib.sha256(message).digest()
    return hashlib.sha256(
        rejection_seed + repr(ciphertext).encode("utf-8")
    ).digest()


if __name__ == "__main__":
    # The demo uses a fixed seed so its output is reproducible - run
    # it and you will see exactly the values in the README example.
    # Real use passes no rng, and then everything is fresh randomness.
    public_key, secret_key = generate_keypair(random.Random(20261106))
    ciphertext, shared_encaps = encaps(public_key, random.Random(20261106))
    shared_decaps = decaps(secret_key, ciphertext)
    print("ML-KEM-style key encapsulation demo - educational only,")
    print("not production cryptography. Real systems use ML-KEM / Kyber (FIPS 203).")
    print(f"Secret dimension: {SECRET_DIMENSION}, "
          f"samples: {NUM_SAMPLES}, modulus: {MODULUS}")
    print(f"Public key:  A[0] = {public_key[0][0]}")
    print(f"             b[0..3] = {public_key[1][:4]}")
    print(f"Secret key:  s[0..3] = {secret_key[0][:4]}")
    print(f"Ciphertext:  {len(ciphertext)} bit-ciphertexts "
          f"({len(ciphertext[0][0])}-element vectors + one value each)")
    print(f"Shared secret (encaps): {shared_encaps.hex()}")
    print(f"Shared secret (decaps): {shared_decaps.hex()}")
    print("Shared secrets match!"
          if shared_encaps == shared_decaps
          else "Shared secrets do NOT match!")
