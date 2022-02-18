import unittest
import main
import rsa

class TestShamir(unittest.TestCase):
    def test_shamir(self):
        # Create the keys and split the private key into k shards
        main.create_keys(2,5)
        # Retrieve the private keys using a list of shards to use to do so
        public_key, private_key = main.retreive_keys([2,5], 5)

        message = "This is a test string"

        ciphertext = rsa.encrypt(message.encode('ascii'), public_key)
        plaintext = rsa.decrypt(ciphertext, private_key).decode('ascii')

        # Assert the decrpyted plain text is equal to the original plain text
        self.assertTrue(message, plaintext)

if __name__ == '__main__':
    unittest.main()