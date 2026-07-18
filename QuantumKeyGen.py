import secrets


def generate_quantum_resistant_key(length=64):
    """Generates a secure random key for post-quantum simulation."""
    return secrets.token_hex(length)


if __name__ == "__main__":
    key = generate_quantum_resistant_key()
    print(f"Generated Quantum-Resistant Key: {key}")
