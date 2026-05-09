import socket
import threading
import logging
import time
from pqc_utils import PQCUtils
from spa_module import SPAModule

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("Gateway")

class PQCGateway:
    def __init__(self, host='127.0.0.1', port=5000, spa_secret="pqc_demo_secret"):
        self.host = host
        self.port = port
        self.spa = SPAModule(spa_secret)
        self.is_open = False
        self.sessions = {} # client_id -> shared_secret

    def start_spa_listener(self):
        """Simulates a silent UDP listener for SPA."""
        logger.info(f"SPA Listener started on {self.host}:UDP/9999 (Hidden)")
        # In a real scenario, this would be a raw socket listening for UDP
        pass

    def handle_knock(self, packet):
        """Processes an incoming SPA knock."""
        if self.spa.verify_knock_packet(packet):
            logger.info("Access Granted. Temporarily opening data port.")
            self.is_open = True
            return True
        return False

    def handle_client(self, conn, addr):
        logger.info(f"Connection from {addr}")
        try:
            if not self.is_open:
                logger.warning("Unauthenticated connection attempt. Closing.")
                conn.close()
                return

            # PQC Handshake (Kyber/ML-KEM)
            # 1. Generate Gateway Keypair
            pub_key, sec_key = PQCUtils.generate_keypair()
            
            # 2. Send Public Key to Client
            conn.sendall(pub_key)
            logger.info("Sent PQC Public Key to client")
            
            # 3. Receive Ciphertext from Client
            ciphertext = conn.recv(2048) # Typical Kyber ciphertext size is < 2KB
            logger.info("Received encrypted secret from client")
            
            # 4. Decapsulate to get Shared Secret
            shared_secret = PQCUtils.decapsulate(ciphertext, sec_key)
            logger.info(f"Established Shared Secret: {shared_secret.hex()[:16]}...")
            
            # Now we have a quantum-secure tunnel session!
            # Send an encrypted "Welcome" (Simplified)
            conn.sendall(b"SECURE_CHANNEL_ESTABLISHED")
            
            # Continue proxying...
            data = conn.recv(1024)
            if data:
                logger.info(f"Received encrypted data: {data.hex()[:20]}...")
                conn.sendall(b"ACK: " + data)

        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            conn.close()
            # self.is_open = False # Re-hide for Zero Trust

    def run(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        logger.info(f"Gateway listening on {self.host}:{self.port}")
        
        while True:
            conn, addr = server.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    gw = PQCGateway()
    # For simulation, we'd normally run this in a thread
    # gw.run()
    logger.info("Gateway source loaded.")
