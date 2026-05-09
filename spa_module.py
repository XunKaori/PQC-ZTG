import hmac
import hashlib
import time
import os
import json
import base64
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SPAModule")

class SPAModule:
    """
    Single Packet Authorization (SPA) implementation.
    """
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode()
        self.time_window = 60 # 60 seconds validity

    def generate_knock_packet(self, client_id: str) -> bytes:
        """
        Generates an encrypted/auth knock packet.
        Format: Base64(json({timestamp, client_id, nonce, hmac}))
        """
        timestamp = int(time.time())
        nonce = os.urandom(16).hex()
        
        payload_str = f"{timestamp}:{client_id}:{nonce}"
        signature = hmac.new(self.secret_key, payload_str.encode(), hashlib.sha256).hexdigest()
        
        packet_data = {
            "t": timestamp,
            "id": client_id,
            "n": nonce,
            "s": signature
        }
        
        return base64.b64encode(json.dumps(packet_data).encode())

    def verify_knock_packet(self, packet_bytes: bytes) -> bool:
        """
        Verifies the knock packet.
        Check HMAC and Time Window.
        """
        try:
            packet_data = json.loads(base64.b64decode(packet_bytes).decode())
            timestamp = packet_data['t']
            client_id = packet_data['id']
            nonce = packet_data['n']
            signature = packet_data['s']
            
            # 1. Check time window
            current_time = int(time.time())
            if abs(current_time - timestamp) > self.time_window:
                logger.warning(f"Knock rejected: Time window expired ({abs(current_time - timestamp)}s)")
                return False
            
            # 2. Verify HMAC
            payload_str = f"{timestamp}:{client_id}:{nonce}"
            expected_sig = hmac.new(self.secret_key, payload_str.encode(), hashlib.sha256).hexdigest()
            
            if hmac.compare_digest(signature, expected_sig):
                logger.info(f"Knock verified successfully for client: {client_id}")
                return True
            else:
                logger.warning("Knock rejected: Invalid signature")
                return False
                
        except Exception as e:
            logger.error(f"Error verifying knock packet: {e}")
            return False

if __name__ == "__main__":
    # Test SPA
    SECRET = "super_secret_pqc_key"
    spa = SPAModule(SECRET)
    
    packet = spa.generate_knock_packet("test_client")
    logger.info(f"Generated Packet: {packet.decode()}")
    
    is_valid = spa.verify_knock_packet(packet)
    logger.info(f"Is Valid: {is_valid}")
