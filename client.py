import socket
import logging
import time
from pqc_utils import PQCUtils
from spa_module import SPAModule

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("Client")

class PQCClient:
    def __init__(self, target_host='127.0.0.1', target_port=5000, spa_secret="pqc_demo_secret"):
        self.target_host = target_host
        self.target_port = target_port
        self.spa = SPAModule(spa_secret)
        self.shared_secret = None

    def knock(self):
        """Sends an SPA knock packet to the gateway."""
        packet = self.spa.generate_knock_packet("user_admin_001")
        logger.info(f"Sending SPA Knock Packet ({len(packet)} bytes)...")
        # In real world, send via UDP to magic port
        # socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(packet, (self.target_host, 9999))
        return packet

    def connect_and_handshake(self):
        """Connects to gateway and performs PQC handshake."""
        try:
            logger.info(f"Connecting to Gateway {self.target_host}:{self.target_port}...")
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((self.target_host, self.target_port))
            
            # PQC Handshake
            # 1. Receive Gateway Public Key
            gw_pub_key = client.recv(2048)
            logger.info("Received Gateway PQC Public Key")
            
            # 2. Encapsulate our secret using their public key
            ciphertext, shared_secret = PQCUtils.encapsulate(gw_pub_key)
            self.shared_secret = shared_secret
            
            # 3. Send Ciphertext to Gateway
            client.sendall(ciphertext)
            logger.info("Sent encapsulated secret to Gateway")
            
            # 4. Wait for confirmation
            response = client.recv(1024)
            if response == b"SECURE_CHANNEL_ESTABLISHED":
                logger.info("Quantum-Safe Tunnel Established successfully!")
                
                # Test data transmission
                test_msg = b"Sensitive Quantum Data"
                client.sendall(test_msg)
                resp = client.recv(1024)
                logger.info(f"Gateway Response: {resp.decode()}")
                
                client.close()
                return True
            else:
                logger.error(f"Handshake failed: {response}")
                client.close()
                return False

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

if __name__ == "__main__":
    client = PQCClient()
    # Step 1: Knock
    client.knock()
    # Step 2: Connect
    # time.sleep(0.5) # Wait for FW update
    # client.connect_and_handshake()
    logger.info("Client source loaded.")
