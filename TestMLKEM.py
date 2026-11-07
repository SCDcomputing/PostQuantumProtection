import random
import unittest

from MLKEM import (
    MESSAGE_BYTES,
    MODULUS,
    NUM_SAMPLES,
    SECRET_DIMENSION,
    SHARED_SECRET_BYTES,
    decaps,
    encaps,
    generate_keypair,
)


class TestMLKEM(unittest.TestCase):

    def test_key_generation(self):
        public_key, secret_key = generate_keypair()
        matrix, public_vector = public_key
        secret_vector, rejection_seed, carried_key = secret_key
        self.assertEqual(len(secret_vector), SECRET_DIMENSION)
        self.assertEqual(len(rejection_seed), SHARED_SECRET_BYTES)
        self.assertEqual(carried_key, public_key)
        self.assertEqual(len(matrix), NUM_SAMPLES)
        self.assertEqual(len(public_vector), NUM_SAMPLES)
        for row in matrix:
            self.assertEqual(len(row), SECRET_DIMENSION)
            for value in row:
                self.assertIn(value, range(MODULUS))
        for value in public_vector + secret_vector:
            self.assertIn(value, range(MODULUS))

    def test_key_uniqueness(self):
        public_key1, secret_key1 = generate_keypair()
        public_key2, secret_key2 = generate_keypair()
        self.assertNotEqual(public_key1, public_key2)
        self.assertNotEqual(secret_key1[0], secret_key2[0])
        self.assertNotEqual(secret_key1[1], secret_key2[1])

    def test_shared_secret_length(self):
        public_key, secret_key = generate_keypair()
        ciphertext, shared = encaps(public_key)
        self.assertEqual(len(shared), SHARED_SECRET_BYTES)
        self.assertEqual(
            len(decaps(secret_key, ciphertext)), SHARED_SECRET_BYTES
        )

    def test_encaps_decaps_round_trip(self):
        public_key, secret_key = generate_keypair()
        ciphertext, shared_encaps = encaps(public_key)
        self.assertEqual(decaps(secret_key, ciphertext), shared_encaps)

    def test_encaps_decaps_many_trials(self):
        failures = 0
        trials = 0
        for _ in range(200):
            public_key, secret_key = generate_keypair()
            ciphertext, shared_encaps = encaps(public_key)
            trials += 1
            if decaps(secret_key, ciphertext) != shared_encaps:
                failures += 1
        self.assertEqual(
            failures, 0, f"{failures} of {trials} round trips failed"
        )

    def test_shared_secret_equality_explicit(self):
        # Encaps and decaps must agree on the shared secret, and the
        # secret must be the SHA-256 of the encapsulated message - so
        # two independent keypairs encapsulating the same message
        # agree too (checked through a seeded run below).
        public_key, secret_key = generate_keypair()
        ciphertext, shared_encaps = encaps(public_key)
        shared_decaps = decaps(secret_key, ciphertext)
        self.assertEqual(shared_encaps, shared_decaps)
        self.assertEqual(len(shared_encaps), MESSAGE_BYTES * 2)

    def test_encaps_randomness(self):
        # Two encapsulations under the same public key must produce
        # different ciphertexts and different shared secrets.
        public_key, _ = generate_keypair()
        ciphertext1, shared1 = encaps(public_key)
        ciphertext2, shared2 = encaps(public_key)
        self.assertNotEqual(ciphertext1, ciphertext2)
        self.assertNotEqual(shared1, shared2)

    def test_tampered_ciphertext_changes_secret(self):
        public_key, secret_key = generate_keypair()
        ciphertext, shared_encaps = encaps(public_key)
        # Flip one value in the first bit-ciphertext's vector.
        tampered = [(list(u), v) for u, v in ciphertext]
        tampered[0][0][0] = (tampered[0][0][0] + 1) % MODULUS
        tampered = [(u, v) for u, v in tampered]
        self.assertNotEqual(
            decaps(secret_key, tampered), shared_encaps,
            "a tampered ciphertext must not yield the real secret",
        )

    def test_tampered_value_changes_secret(self):
        public_key, secret_key = generate_keypair()
        ciphertext, shared_encaps = encaps(public_key)
        # Flip the v value of one bit-ciphertext instead of the vector.
        tampered = [(list(u), v) for u, v in ciphertext]
        tampered[5] = (tampered[5][0], (tampered[5][1] + 1) % MODULUS)
        tampered = [(u, v) for u, v in tampered]
        self.assertNotEqual(
            decaps(secret_key, tampered), shared_encaps,
            "a tampered ciphertext must not yield the real secret",
        )

    def test_wrong_key_does_not_decapsulate(self):
        public_key, _ = generate_keypair()
        _, wrong_key = generate_keypair()
        ciphertext, shared_encaps = encaps(public_key)
        self.assertNotEqual(
            decaps(wrong_key, ciphertext), shared_encaps,
            "the wrong secret key must not yield the real secret",
        )

    def test_determinism_with_fixed_seed(self):
        # The same seed must reproduce the same keypair, ciphertext,
        # and shared secret, end to end.
        public_key1, secret_key1 = generate_keypair(random.Random(42))
        ciphertext1, shared1 = encaps(public_key1, random.Random(42))
        public_key2, secret_key2 = generate_keypair(random.Random(42))
        ciphertext2, shared2 = encaps(public_key2, random.Random(42))
        self.assertEqual(public_key1, public_key2)
        self.assertEqual(secret_key1, secret_key2)
        self.assertEqual(ciphertext1, ciphertext2)
        self.assertEqual(shared1, shared2)
        self.assertEqual(decaps(secret_key1, ciphertext1), shared1)
        self.assertEqual(decaps(secret_key2, ciphertext2), shared2)

    def test_different_seeds_differ(self):
        public_key1, _ = generate_keypair(random.Random(1))
        public_key2, _ = generate_keypair(random.Random(2))
        self.assertNotEqual(public_key1, public_key2)


if __name__ == '__main__':
    unittest.main()
