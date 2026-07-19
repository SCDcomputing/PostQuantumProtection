import unittest
from QuantumKeyGen import generate_quantum_resistant_key

class TestQuantumKeyGen(unittest.TestCase):

    def test_key_generation(self):
        key = generate_quantum_resistant_key(64)
        self.assertEqual(len(key), 128)

    def test_key_uniqueness(self):
        key1 = generate_quantum_resistant_key(64)
        key2 = generate_quantum_resistant_key(64)
        self.assertNotEqual(key1, key2)

if __name__ == '__main__':
    unittest.main()
