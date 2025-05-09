# full_node.py

from concurrent import futures
import grpc
import time
import threading
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

import block_chain_pb2
import block_chain_pb2_grpc
import common_pb2
import file_audit_pb2
import file_audit_pb2_grpc

# Global mempool
mempool = []

# List of neighbor nodes (to be configured)
NEIGHBOR_NODES = [
    "localhost:50052",
    "localhost:50053"
]

def calculate_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def generate_merkle_root(audits):
    # Dummy Merkle root: concatenate req_ids and hash
    concat = "".join([audit.req_id for audit in audits])
    return calculate_hash(concat)

def remove_from_mempool(audits):
    """Remove processed audits from mempool after consensus"""
    global mempool
    for audit in audits:
        if audit in mempool:
            mempool.remove(audit)
            print(f"Removed audit {audit.req_id} from mempool")

def build_block():
    global mempool
    if not mempool:
        print("No audits in mempool to propose a block.")
        return None

    print("\nProposing a new block...")

    timestamp = int(time.time())
    block_number = 1  # Static for now
    previous_block_hash = "genesis"
    merkle_root = generate_merkle_root(mempool)
    block_hash = calculate_hash(f"{previous_block_hash}{timestamp}{merkle_root}")

    block = block_chain_pb2.Block(
        block_hash=block_hash,
        previous_block_hash=previous_block_hash,
        merkle_root=merkle_root,
        block_number=block_number,
        timestamp=timestamp,
        proposer_id="node-001",
        audits=mempool
    )

    proposal = block_chain_pb2.BlockProposal(
        block=block,
        proposer_id="node-001",
        timestamp=timestamp
    )

    print("📦 Block Proposed:")
    print(proposal)

    # TODO: This will be called after consensus is reached
    # For now, we'll simulate consensus by removing from mempool
    remove_from_mempool(mempool)

    return proposal

def verify_audit(audit: common_pb2.FileAudit) -> bool:
    """Verify the signature of an audit request"""
    try:
        # Load public key
        public_key = serialization.load_pem_public_key(
            audit.public_key.encode(), 
            backend=default_backend()
        )

        # Remove signature/public_key before verifying
        stripped_request = common_pb2.FileAudit(
            req_id=audit.req_id,
            file_info=audit.file_info,
            user_info=audit.user_info,
            access_type=audit.access_type,
            timestamp=audit.timestamp,
        )

        # Verify signature
        public_key.verify(
            bytes.fromhex(audit.signature),
            stripped_request.SerializeToString(deterministic=True),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed for audit {audit.req_id}: {e}")
        return False

def whisper_to_neighbors(audit: common_pb2.FileAudit):
    """Whisper the audit request to all neighbor nodes"""
    for neighbor in NEIGHBOR_NODES:
        try:
            channel = grpc.insecure_channel(neighbor)
            stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
            response = stub.WhisperAuditRequest(audit)
            print(f"Whispered to {neighbor}: {response.status}")
        except Exception as e:
            print(f"Failed to whisper to {neighbor}: {e}")

class BlockChainServiceServicer(block_chain_pb2_grpc.BlockChainServiceServicer):
    def WhisperAuditRequest(self, request, context):
        try:
            # Verify the audit
            if not verify_audit(request):
                return block_chain_pb2.WhisperResponse(
                    status="failure", 
                    error="Signature verification failed"
                )

            # Add to mempool if not already present
            if request not in mempool:
                mempool.append(request)
                print(f"Audit {request.req_id} added to mempool")
                return block_chain_pb2.WhisperResponse(status="success")
            else:
                print(f"Audit {request.req_id} already in mempool")
                return block_chain_pb2.WhisperResponse(status="success")

        except Exception as e:
            print(f"Error processing audit {request.req_id}: {e}")
            return block_chain_pb2.WhisperResponse(
                status="failure", 
                error=str(e)
            )

class FileAuditServiceServicer(file_audit_pb2_grpc.FileAuditServiceServicer):
    def SubmitAudit(self, request, context):
        try:
            # Verify the audit
            if not verify_audit(request):
                return file_audit_pb2.FileAuditResponse(
                    req_id=request.req_id,
                    status="failure",
                    error_message="Signature verification failed"
                )

            # Add to mempool if not already present
            if request not in mempool:
                mempool.append(request)
                print(f"Audit {request.req_id} added to mempool")
                
                # Whisper to neighbors
                whisper_to_neighbors(request)
                
                return file_audit_pb2.FileAuditResponse(
                    req_id=request.req_id,
                    status="success"
                )
            else:
                print(f"Audit {request.req_id} already in mempool")
                return file_audit_pb2.FileAuditResponse(
                    req_id=request.req_id,
                    status="success"
                )

        except Exception as e:
            print(f"Error processing audit {request.req_id}: {e}")
            return file_audit_pb2.FileAuditResponse(
                req_id=request.req_id,
                status="failure",
                error_message=str(e)
            )

def proposer_loop():
    while True:
        time.sleep(20)
        build_block()

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    
    # Add both services
    block_chain_pb2_grpc.add_BlockChainServiceServicer_to_server(
        BlockChainServiceServicer(), 
        server
    )
    file_audit_pb2_grpc.add_FileAuditServiceServicer_to_server(
        FileAuditServiceServicer(),
        server
    )
    
    server.add_insecure_port("[::]:50051")
    server.start()
    print("Full Node running on port 50051...")

    threading.Thread(target=proposer_loop, daemon=True).start()

    server.wait_for_termination()

if __name__ == "__main__":
    serve()
