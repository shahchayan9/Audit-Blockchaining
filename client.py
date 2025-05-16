import time
import grpc
import logging
import random
import uuid
import base64
from typing import Optional, List, Dict
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import common_pb2
import file_audit_pb2
import file_audit_pb2_grpc
import json

# AI Generated Code for file formatting, logging, and try-catch blocks
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AuditClient:
    DEFAULT_NODE_ADDRESS = '169.254.13.100:50051'
    DEFAULT_PRIVATE_KEY_PATH = 'private_key.pem'
    DEFAULT_PUBLIC_KEY_PATH = 'public_key.pem'
    DEFAULT_OPERATION_INTERVAL = 2.0
    DEFAULT_SIMULATION_DURATION = 6
    
    # AI Generated Code for initializing the client
    def __init__(self, 
                 node_address: str = DEFAULT_NODE_ADDRESS,
                 private_key_path: str = DEFAULT_PRIVATE_KEY_PATH,
                 public_key_path: str = DEFAULT_PUBLIC_KEY_PATH):
        self.node_address = node_address
        self.private_key = self._load_private_key(private_key_path)
        self.public_key_str = self._load_public_key(public_key_path)
        self.stub = self._create_stub()
        
        self.files = {
            "doc1.txt": {"id": "f001", "name": "doc1.txt", "content": "Initial content"},
            "data.csv": {"id": "f002", "name": "data.csv", "content": "1,2,3"},
            "report.pdf": {"id": "f003", "name": "report.pdf", "content": "PDF content"},
            "config.json": {"id": "f004", "name": "config.json", "content": "{}"},
            "temp.txt": {"id": "f005", "name": "temp.txt", "content": "temporary"}
        }
        
        self.users = [
            {"id": "u001", "name": "alice"},
            {"id": "u002", "name": "bob"},
            {"id": "u003", "name": "charlie"}
        ]

    # AI Generated Code for loading public & private keys
    def _load_private_key(self, key_path: str):
        try:
            with open(key_path, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            raise

    def _load_public_key(self, key_path: str) -> str:
        try:
            with open(key_path, "rb") as f:
                return f.read().decode()
        except Exception as e:
            logger.error(f"Failed to load public key: {e}")
            raise

    # AI Generated Code for creating gRPC stub
    def _create_stub(self) -> file_audit_pb2_grpc.FileAuditServiceStub:
        try:
            channel = grpc.insecure_channel(self.node_address)
            return file_audit_pb2_grpc.FileAuditServiceStub(channel)
        except Exception as e:
            logger.error(f"Failed to create gRPC stub: {e}")
            raise

    def _sign_audit(self, audit: common_pb2.FileAudit) -> str:
        try:
            audit_data = {
                "req_id": audit.req_id,
                "file_info": {
                    "file_id": audit.file_info.file_id,
                    "file_name": audit.file_info.file_name
                },
                "user_info": {
                    "user_id": audit.user_info.user_id,
                    "user_name": audit.user_info.user_name
                },
                "access_type": audit.access_type,
                "timestamp": audit.timestamp
            }
            
            msg_bytes = json.dumps(audit_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
            signature = self.private_key.sign(
                msg_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return base64.b64encode(signature).decode()
        except Exception as e:
            logger.error(f"Failed to sign audit: {e}")
            raise

    def create_audit(
        self,
        req_id: str,
        file_id: str,
        file_name: str,
        user_id: str,
        user_name: str,
        access_type: common_pb2.AccessType
    ) -> common_pb2.FileAudit:
        try:
            audit_data = {
                "req_id": req_id,
                "file_info": {
                    "file_id": file_id,
                    "file_name": file_name
                },
                "user_info": {
                    "user_id": user_id,
                    "user_name": user_name
                },
                "access_type": access_type,
                "timestamp": int(time.time())
            }

            audit = common_pb2.FileAudit(
                req_id=audit_data["req_id"],
                file_info=common_pb2.FileInfo(
                    file_id=audit_data["file_info"]["file_id"],
                    file_name=audit_data["file_info"]["file_name"]
                ),
                user_info=common_pb2.UserInfo(
                    user_id=audit_data["user_info"]["user_id"],
                    user_name=audit_data["user_info"]["user_name"]
                ),
                access_type=audit_data["access_type"],
                timestamp=audit_data["timestamp"]
            )

            audit.signature = self._sign_audit(audit)
            audit.public_key = self.public_key_str

            return audit
        except Exception as e:
            logger.error(f"Failed to create audit: {e}")
            raise

    def submit_audit(self, audit: common_pb2.FileAudit) -> Optional[file_audit_pb2.FileAuditResponse]:
        try:
            response = self.stub.SubmitAudit(audit)
            logger.info(f"Audit {audit.req_id} submitted successfully: {response.status}")
            return response
        except grpc.RpcError as e:
            logger.error(f"gRPC error submitting audit {audit.req_id}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error submitting audit {audit.req_id}: {e}")
            return None

    def simulate_file_operation(self):
        file_name = random.choice(list(self.files.keys()))
        file_info = self.files[file_name]
        user = random.choice(self.users)
        
        operation = random.choices(
            [common_pb2.READ, common_pb2.UPDATE, common_pb2.WRITE],
            weights=[0.6, 0.3, 0.1]
        )[0]
        
        audit = self.create_audit(
            req_id=str(uuid.uuid4()),
            file_id=file_info["id"],
            file_name=file_name,
            user_id=user["id"],
            user_name=user["name"],
            access_type=operation
        )
        
        operation_name = {
            common_pb2.READ: "READ",
            common_pb2.UPDATE: "UPDATE",
            common_pb2.WRITE: "WRITE"
        }[operation]
        
        logger.info(f"Simulating {operation_name} operation: User {user['name']} on file {file_name}")
        
        self.submit_audit(audit)
        
        if operation == common_pb2.WRITE:
            file_info["content"] = f"Wrote content at {datetime.now()}"
        elif operation == common_pb2.UPDATE:
            file_info["content"] = f"Updated content at {datetime.now()}"
        elif operation == common_pb2.READ:
            file_info["content"] = f"Read content at {datetime.now()}"

    # AI Generated Code for running the simulation
    def run_simulation(self, 
                      duration: int = DEFAULT_SIMULATION_DURATION,
                      interval: float = DEFAULT_OPERATION_INTERVAL) -> bool:
        try:
            logger.info(f"Starting simulation for {duration} seconds with {interval}s intervals")
            start_time = time.time()
            
            while time.time() - start_time < duration:
                self.simulate_file_operation()
                time.sleep(interval)
                
            logger.info("Simulation completed")
            return True
            
        except Exception as e:
            logger.error(f"Simulation error: {e}")
            return False

def main():
    client = AuditClient()
    client.run_simulation()

if __name__ == "__main__":
    exit(0 if main() else 1)
