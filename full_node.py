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

# Global mempool
mempool = []

def calculate_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def generate_merkle_root(audits):
    # Dummy Merkle root: concatenate req_ids and hash
    concat = "".join([audit.req_id for audit in audits])
    return calculate_hash(concat)

def build_block():
    global mempool
    if not mempool:
        print("⏳ No audits in mempool to propose a block.")
        return None

    print("\n🏗️  Proposing a new block...")

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

    # DO NOT clear mempool yet – that's done after consensus (next chunk)
    return proposal

class BlockChainServiceServicer(block_chain_pb2_grpc.BlockChainServiceServicer):
    def WhisperAuditRequest(self, request, context):
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                request.public_key.encode(), backend=default_backend()
            )

            # Remove signature/public_key before verifying
            stripped_request = common_pb2.FileAudit(
                req_id=request.req_id,
                file_info=request.file_info,
                user_info=request.user_info,
                access_type=request.access_type,
                timestamp=request.timestamp,
            )

            public_key.verify(
                bytes.fromhex(request.signature),
                stripped_request.SerializeToString(deterministic=True),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            mempool.append(request)
            print(f"✅ Audit {request.req_id} added to mempool")
            return block_chain_pb2.WhisperResponse(status="success")

        except Exception as e:
            print(f"❌ Verification failed for audit {request.req_id}: {e}")
            return block_chain_pb2.WhisperResponse(status="failure", error=str(e))

def proposer_loop():
    while True:
        time.sleep(20)
        build_block()

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    block_chain_pb2_grpc.add_BlockChainServiceServicer_to_server(BlockChainServiceServicer(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    print("🚀 Full Node running on port 50051...")

    threading.Thread(target=proposer_loop, daemon=True).start()

    server.wait_for_termination()

if __name__ == "__main__":
    serve()
