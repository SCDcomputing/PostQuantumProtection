import random
import unittest

from LatticeCrypto import (
    MODULUS,
    NUM_SAMPLES,
    SECRET_DIMENSION,
    decrypt_bit,
    decrypt_message,
    encrypt_bit,
    encrypt_message,
    generate_keypair,
)


class TestLatticeCrypto(unittest.TestCase):

    def test_key_generation(self):
        public_key, secret_key = generate_keypair()
        matrix, public_vector = public_key
        self.assertEqual(len(secret_key), SECRET_DIMENSION)
        self.assertEqual(len(matrix), NUM_SAMPLES)
        self.assertEqual(len(public_vector), NUM_SAMPLES)
        for row in matrix:
            self.assertEqual(len(row), SECRET_DIMENSION)
            for value in row:
                self.assertIn(value, range(MODULUS))
        for value in public_vector + secret_key:
            self.assertIn(value, range(MODULUS))

    def test_key_uniqueness(self):
        public_key1, secret_key1 = generate_keypair()
        public_key2, secret_key2 = generate_keypair()
        self.assertNotEqual(public_key1, public_key2)
        self.assertNotEqual(secret_key1, secret_key2)

    def test_bit_round_trip(self):
        public_key, secret_key = generate_keypair()
        for bit in (0, 1):
            for _ in range(50):
                ciphertext = encrypt_bit(public_key, bit)
                self.assertEqual(decrypt_bit(secret_key, ciphertext), bit)

    def test_message_round_trip_examples(self):
        public_key, secret_key = generate_keypair()
        for message in ["", "A", "Hello, lattice!", "1234567890"]:
            ciphertexts = encrypt_message(public_key, message)
            self.assertEqual(decrypt_message(secret_key, ciphertexts), message)

    def test_message_round_trip_unicode(self):
        public_key, secret_key = generate_keypair()
        message = "héllo wörld"
        ciphertexts = encrypt_message(public_key, message)
        self.assertEqual(decrypt_message(secret_key, ciphertexts), message)

    def test_message_round_trip_many_trials(self):
        rng = random.Random(20261106)
        alphabet = (
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789 ,.!?"
        )
        failures = 0
        trials = 0
        for _ in range(200):
            length = rng.randrange(0, 21)
            message = "".join(rng.choice(alphabet) for _ in range(length))
            public_key, secret_key = generate_keypair()
            ciphertexts = encrypt_message(public_key, message)
            decrypted = decrypt_message(secret_key, ciphertexts)
            trials += 1
            if decrypted != message:
                failures += 1
        self.assertEqual(
            failures, 0, f"{failures} of {trials} round trips failed"
        )

    def test_different_keys_different_ciphertexts(self):
        message = "Same message"
        public_key1, _ = generate_keypair()
        public_key2, _ = generate_keypair()
        self.assertNotEqual(
            encrypt_message(public_key1, message),
            encrypt_message(public_key2, message),
        )

    def test_same_message_encrypts_differently(self):
        public_key, _ = generate_keypair()
        message = "Same message"
        self.assertNotEqual(
            encrypt_message(public_key, message),
            encrypt_message(public_key, message),
        )

    def test_wrong_key_does_not_decrypt(self):
        message = "Hello, lattice! This must not come back."
        public_key, _ = generate_keypair()
        _, wrong_key = generate_keypair()
        ciphertexts = encrypt_message(public_key, message)
        self.assertNotEqual(decrypt_message(wrong_key, ciphertexts), message)

    def test_invalid_bit_rejected(self):
        public_key, _ = generate_keypair()
        with self.assertRaises(ValueError):
            encrypt_bit(public_key, 2)


if __name__ == '__main__':
    unittest.main()
