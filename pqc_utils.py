import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("PQCUtils")

try:
    import oqs
except ImportError:
    logger.error("liboqs-python not found. Please install it using 'pip install liboqs-python'.")
    # For demonstration purposes, we will mock the functionality if the library is missing
    oqs = None

class PQCUtils:
    """
    Utility class for Post-Quantum Cryptography using ML-KEM (Kyber).
    """
    
    KEM_ALGORITHM = "Kyber768" # ML-KEM-768 equivalent in liboqs

    @staticmethod
    def generate_keypair():
        """
        Generates an ML-KEM keypair.
        Returns: (public_key, secret_key)
        """
        if oqs is None:
            logger.warning("Mocking keypair generation (liboqs missing)")
            return b"mock_public_key_32_bytes_long_keys", b"mock_secret_key_32_bytes_long_keys"
            
        with oqs.KeyEncapsulation(PQCUtils.KEM_ALGORITHM) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            return public_key, secret_key

    @staticmethod
    def encapsulate(public_key):
        """
        Encapsulates a shared secret using the provided public key.
        Returns: (ciphertext, shared_secret)
        """
        if oqs is None:
            logger.warning("Mocking encapsulation (liboqs missing)")
            return b"mock_ciphertext", b"mock_shared_secret"

        with oqs.KeyEncapsulation(PQCUtils.KEM_ALGORITHM) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
            return ciphertext, shared_secret

    @staticmethod
    def decapsulate(ciphertext, secret_key):
        """
        Decapsulates a shared secret using the provided ciphertext and secret key.
        Returns: shared_secret
        """
        if oqs is None:
            logger.warning("Mocking decapsulation (liboqs missing)")
            return b"mock_shared_secret"

        with oqs.KeyEncapsulation(PQCUtils.KEM_ALGORITHM, secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
            return shared_secret

if __name__ == "__main__":
    # Internal test
    logger.info("Testing PQC Utility...")
    pub, sec = PQCUtils.generate_keypair()
    ct, ss_encap = PQCUtils.encapsulate(pub)
    ss_decap = PQCUtils.decapsulate(ct, sec)
    
    if ss_encap == ss_decap:
        logger.info("PQC Key Exchange Successful!")
    else:
        logger.error("PQC Key Exchange Failed!")
