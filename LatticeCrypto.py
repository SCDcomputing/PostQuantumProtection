"""Lattice-based cryptography: a Regev-style Learning With Errors (LWE)
public-key encryption demonstration.

EDUCATIONAL DEMONSTRATION ONLY - NOT production-grade cryptography.
This module is a small, readable teaching example of how lattice-based
encryption works. It uses tiny toy parameters (secret dimension 16,
modulus 257) that are trivially breakable, has no protection against
side-channel or chosen-ciphertext attacks, and must NEVER be used to
protect real data.

Real post-quantum systems use standardized algorithms such as ML-KEM
(Kyber, FIPS 203) and ML-DSA (Dilithium, FIPS 204), which use much
larger parameters, rejection sampling, and the module-LWE construction.
If you need quantum-resistant encryption in production, use a vetted
library that implements those standards - do not adapt this demo.

How it works (Regev's LWE cryptosystem, simplified):
  - The secret key is a random vector s.
  - The public key is a random matrix A and a vector b = A*s + e,
    where e is a vector of tiny random errors. Recovering s from
    (A, b) is the Learning With Errors problem, which is believed to
    be hard for properly chosen parameters - and it is the hardness
    that lattice-based cryptography rests on.
  - To encrypt one bit, pick a random subset of the public-key rows,
    add them up, and shift the result by half the modulus if the
    bit is 1.
  - To decrypt, subtract the secret-key combination and check
    whether the result is closer to 0 or to half the modulus.

The demo parameters are chosen so decryption is reliable: every
error is -1, 0, or 1 and at most 32 of them are ever added together,
so the total noise is at most 32 - well under a quarter of the
modulus (257 / 4 is about 64).
"""

import secrets

# --- Demo parameters (toy-sized; NOT secure, see the warning above) ---
SECRET_DIMENSION = 16   # length of the secret vector s (n)
NUM_SAMPLES = 32        # number of rows in the public key (m)
MODULUS = 257           # prime modulus (q); all arithmetic is mod 257
ERROR_BOUND = 1         # each error is drawn uniformly from {-1, 0, 1}
HALF_MODULUS = MODULUS // 2   # 128: the shift that encodes a 1 bit


def _random_mod_q():
    """Return a uniform random value in Z_q."""
    return secrets.randbelow(MODULUS)


def _sample_error():
    """Return a small error, uniformly drawn from {-1, 0, 1}."""
    return secrets.randbelow(2 * ERROR_BOUND + 1) - ERROR_BOUND


def generate_keypair():
    """Generate an LWE keypair.

    Returns:
        (public_key, secret_key) where the public key is (A, b):
        A is a list of NUM_SAMPLES rows, each a list of
        SECRET_DIMENSION values in Z_q, and b is a list of
        NUM_SAMPLES values in Z_q with b = A*s + e (mod q).
        The secret key is a list of SECRET_DIMENSION values in Z_q.
    """
    secret_key = [_random_mod_q() for _ in range(SECRET_DIMENSION)]
    matrix = [
        [_random_mod_q() for _ in range(SECRET_DIMENSION)]
        for _ in range(NUM_SAMPLES)
    ]
    errors = [_sample_error() for _ in range(NUM_SAMPLES)]
    public_vector = [
        (sum(a * s for a, s in zip(row, secret_key)) + e) % MODULUS
        for row, e in zip(matrix, errors)
    ]
    return (matrix, public_vector), secret_key


def encrypt_bit(public_key, bit):
    """Encrypt a single bit (0 or 1) under the public key.

    Returns a ciphertext (u, v): u is a list of SECRET_DIMENSION
    values in Z_q and v is a single value in Z_q.
    """
    if bit not in (0, 1):
        raise ValueError("bit must be 0 or 1")
    matrix, public_vector = public_key
    subset = [secrets.randbelow(2) for _ in range(NUM_SAMPLES)]
    u = [
        sum(r * row[j] for r, row in zip(subset, matrix)) % MODULUS
        for j in range(SECRET_DIMENSION)
    ]
    v = (
        sum(r * b for r, b in zip(subset, public_vector))
        + bit * HALF_MODULUS
    ) % MODULUS
    return u, v


def decrypt_bit(secret_key, ciphertext):
    """Decrypt a single-bit ciphertext (u, v) with the secret key.

    Returns 0 or 1.
    """
    u, v = ciphertext
    noise = (v - sum(a * s for a, s in zip(u, secret_key))) % MODULUS
    # noise is near 0 for a 0 bit and near HALF_MODULUS for a 1 bit;
    # the midpoint between them is a quarter of the modulus.
    if MODULUS // 4 <= noise < 3 * MODULUS // 4:
        return 1
    return 0


def _text_to_bits(text):
    """Encode a string as a list of bits (UTF-8, most significant first)."""
    bits = []
    for byte in text.encode("utf-8"):
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bits_to_text(bits):
    """Decode a list of bits back to a string (lossy on bad bytes)."""
    byte_values = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        byte_values.append(byte)
    return byte_values.decode("utf-8", errors="replace")


def encrypt_message(public_key, message):
    """Encrypt a short string. Returns a list of per-bit ciphertexts."""
    return [encrypt_bit(public_key, bit) for bit in _text_to_bits(message)]


def decrypt_message(secret_key, ciphertexts):
    """Decrypt a list of per-bit ciphertexts back to a string."""
    return _bits_to_text([decrypt_bit(secret_key, ct) for ct in ciphertexts])


if __name__ == "__main__":
    MESSAGE = "Hello, lattice!"
    public_key, secret_key = generate_keypair()
    ciphertexts = encrypt_message(public_key, MESSAGE)
    decrypted = decrypt_message(secret_key, ciphertexts)
    print("Lattice-based (LWE) encryption demo - educational only,")
    print("not production cryptography. Real systems use ML-KEM / Kyber.")
    print(f"Secret dimension: {SECRET_DIMENSION}, "
          f"samples: {NUM_SAMPLES}, modulus: {MODULUS}")
    print(f"Original message:  {MESSAGE}")
    print(f"Ciphertext bits:   {len(ciphertexts)} "
          f"({len(ciphertexts[0][0])}-element vectors + one value each)")
    print(f"Decrypted message: {decrypted}")
    print("Success!" if decrypted == MESSAGE else "Decryption failed!")
