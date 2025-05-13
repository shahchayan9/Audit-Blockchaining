# full_node.py

import os
import json
import logging
from concurrent import futures
import grpc
import time
import threading
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from typing import List, Dict, Set, Optional
import base64

import block_chain_pb2
import block_chain_pb2_grpc
import common_pb2
import file_audit_pb2
import file_audit_pb2_grpc

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state
mempool: List[common_pb2.FileAudit] = []
confirmed_blocks: Dict[int, block_chain_pb2.Block] = {}
current_block_number = 0
votes_received: Dict[str, List[block_chain_pb2.BlockVoteResponse]] = {}
NEIGHBOR_NODES = [
    "169.254.103.61:50052",   # sameer
    "169.254.162.53:50051",   # serhat
    "169.254.183.161:50051",  # harsha
    "169.254.55.120:50051",    # brandon
    "169.254.103.106:50051",   # jayasurya
    "169.254.137.247:50051",   # ronak
    "169.254.159.92:50053"     # suriya
]
BLOCKS_DIR = "blocks"
MAX_BLOCK_SIZE = 100  # Maximum number of audits per block
MIN_MEMPOOL_SIZE = 3  # Minimum number of audits required to propose a block
NODE_ADDRESS = "169.254.13.100:50051"  # Your WSL IP address

def ensure_blocks_directory():
    """Ensure the blocks directory exists"""
    if not os.path.exists(BLOCKS_DIR):
        os.makedirs(BLOCKS_DIR)
        logger.info(f"Created blocks directory at {BLOCKS_DIR}")

def calculate_hash(data: bytes) -> str:
    """Calculate SHA-256 hash of input data"""
    return hashlib.sha256(data).hexdigest()    
    
def is_leader() -> bool:
    """Determine if this node is the current leader"""
    return True  # Always return true as requested

def get_audit_json(audit: common_pb2.FileAudit) -> str:
    """Convert audit to JSON format"""
    audit_data = {
        "access_type": audit.access_type,
        "file_info": {
            "file_id": audit.file_info.file_id,
            "file_name": audit.file_info.file_name
        },
        "req_id": audit.req_id,
        "timestamp": audit.timestamp,
        "user_info": {
            "user_id": audit.user_info.user_id,
            "user_name": audit.user_info.user_name
        }
    }
    return json.dumps(audit_data, sort_keys=True, separators=(",", ":"))

def verify_audit(audit: common_pb2.FileAudit) -> bool:
    """Verify the signature of an audit request"""
    try:
        # Use the public key from the audit request
        public_key = serialization.load_pem_public_key(
            audit.public_key.encode(), 
            backend=default_backend()
        )

        # Create the audit data structure to verify
        data_to_verify = get_audit_json(audit).encode('utf-8')
        signature_bytes = base64.b64decode(audit.signature)

        public_key.verify(
            signature_bytes,
            data_to_verify,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Log the operation type
        operation_name = {
            common_pb2.READ: "READ",
            common_pb2.UPDATE: "UPDATE",
            common_pb2.WRITE: "WRITE"
        }.get(audit.access_type, "UNKNOWN")
        
        logger.info(f"Successfully verified {operation_name} audit {audit.req_id} for file {audit.file_info.file_name}")
        return True
    except Exception as e:
        logger.error(f"Verification failed for audit {audit.req_id}: {e}")
        return False

def whisper_to_neighbors(audit: common_pb2.FileAudit):
    """Whisper the audit request to all neighbor nodes"""
    for neighbor in NEIGHBOR_NODES:
        try:
            channel = grpc.insecure_channel(neighbor)
            stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
            response = stub.WhisperAuditRequest(audit)
            logger.info(f"Whispered to {neighbor}: {response.status}")
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                logger.warning(f"Node {neighbor} is currently unavailable")
            else:
                logger.error(f"Failed to whisper to {neighbor}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error whispering to {neighbor}: {e}")

def save_block_to_disk(block: block_chain_pb2.Block):
    """Save a confirmed block to disk"""
    ensure_blocks_directory()
    filename = os.path.join(BLOCKS_DIR, f"block_{block.id}.json")
    
    # Convert protobuf objects to dictionaries
    block_dict = {
        "id": block.id,
        "hash": block.hash,
        "previous_hash": block.previous_hash,
        "merkle_root": block.merkle_root,
        "audits": [
            {
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
                "timestamp": audit.timestamp,
                "signature": audit.signature,
                "public_key": audit.public_key
            }
            for audit in block.audits
        ]
    }
    
    with open(filename, 'w') as f:
        json.dump(block_dict, f, indent=2)
    logger.info(f"Block {block.id} saved to {filename}")

def load_last_block() -> int:
    """Load the last block number from disk"""
    ensure_blocks_directory()
    block_files = [f for f in os.listdir(BLOCKS_DIR) if f.startswith("block_") and f.endswith(".json")]
    if not block_files:
        logger.info("No existing blocks found, starting from block 0")
        return 0
    
    block_numbers = [int(f.split("_")[1].split(".")[0]) for f in block_files]
    last_block = max(block_numbers)
    logger.info(f"Loaded last block number: {last_block}")
    return last_block

def generate_merkle_root(audits: List[common_pb2.FileAudit]) -> str:
    """Generate Merkle root from list of audits"""
    if not audits:
        return ""
    
    # Create list of hashes from audits
    hashes = []
    for audit in audits:
        # Hash the JSON string
        hashes.append(calculate_hash(get_audit_json(audit).encode()))
    
    # Build Merkle tree
    while len(hashes) > 1:
        new_hashes = []
        for i in range(0, len(hashes), 2):
            left = hashes[i]
            right = hashes[i + 1] if i + 1 < len(hashes) else left
            new_hashes.append(calculate_hash((left + right).encode()))
        hashes = new_hashes
    
    return hashes[0] if hashes else ""

def verify_block(block: block_chain_pb2.Block) -> bool:
    """Verify a block's validity"""
    try:
        # Verify previous block hash
        if block.id > 1:
            prev_block = confirmed_blocks.get(block.id - 1)
            if not prev_block or prev_block.hash != block.previous_hash:
                logger.error("Invalid previous block hash")
                return False
        
        # Verify Merkle root
        calculated_root = generate_merkle_root(block.audits)
        logger.info(f"Calculated Merkle root: {calculated_root}")
        logger.info(f"Block Merkle root: {block.merkle_root}")
        if calculated_root != block.merkle_root:
            logger.error("Invalid Merkle root")
            return False
        
        # Verify block hash
        audits_string = "".join([get_audit_json(audit) for audit in block.audits])
        block_hash = calculate_hash(f"{block.id}{block.previous_hash}{block.merkle_root}{audits_string}".encode())
        if block_hash != block.hash:
            logger.error("Invalid block hash")
            return False
        
        logger.info(f"Successfully verified block {block.id}")
        return True
    except Exception as e:
        logger.error(f"Block verification failed: {e}")
        return False

def broadcast_proposal(block: block_chain_pb2.Block):
    """Broadcast block proposal to all neighbors and process their votes"""
    global current_block_number
    
    if not NEIGHBOR_NODES:
        # Single node operation - auto confirm the block
        logger.info("No neighbors - auto confirming block")
        confirmed_blocks[block.id] = block
        current_block_number = block.id  # Update current_block_number
        save_block_to_disk(block)
        return

    # Initialize votes for this block
    votes_received[str(block.id)] = []
    
    for neighbor in NEIGHBOR_NODES:
        try:
            channel = grpc.insecure_channel(neighbor)
            stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
            response = stub.ProposeBlock(block)
            logger.info(f"Proposal sent to {neighbor}: {response.status}")
            
            # Add vote to received votes
            if response.status == "success" and response.vote:
                votes_received[str(block.id)].append(response)
                logger.info(f"Received yes vote from {neighbor} for block {block.id}")
                
        except Exception as e:
            logger.error(f"Failed to send proposal to {neighbor}: {e}")
    
    # After collecting all votes, check if we have full consensus
    if len(votes_received[str(block.id)]) == len(NEIGHBOR_NODES):
        logger.info(f"Block {block.id} received full consensus: ({len(votes_received[str(block.id)])} votes)")
        
        # First save the block to disk
        confirmed_blocks[block.id] = block
        save_block_to_disk(block)
        current_block_number = block.id
        
        # Then remove audits from mempool
        for audit in block.audits:
            if audit in mempool:
                mempool.remove(audit)
                logger.info(f"Removed audit {audit.req_id} from mempool")
        
        # Finally notify all neighbors to commit the block
        for neighbor in NEIGHBOR_NODES:
            try:
                channel = grpc.insecure_channel(neighbor)
                stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
                response = stub.CommitBlock(block)
                logger.info(f"Commit request sent to {neighbor}: {response.status}")
            except Exception as e:
                logger.error(f"Failed to send commit request to {neighbor}: {e}")
    else:
        logger.warning(f"Block {block.id} did not receive full consensus ({len(votes_received[str(block.id)])}/{len(NEIGHBOR_NODES)} votes)")
    
    # Clean up votes
    del votes_received[str(block.id)]

def build_block() -> Optional[block_chain_pb2.Block]:
    """Build a new block proposal"""
    global mempool, current_block_number
    
    if not is_leader():
        logger.info(f"Not the leader for block {current_block_number}, skipping proposal")
        return None
        
    if len(mempool) < MIN_MEMPOOL_SIZE:
        logger.info(f"Mempool size {len(mempool)} is below threshold {MIN_MEMPOOL_SIZE}")
        return None

    # Check if we're already waiting for votes on the next block
    if str(current_block_number) in votes_received and NEIGHBOR_NODES:  # Only check if we have neighbors
        logger.info(f"Already waiting for votes on block {current_block_number}")
        return None

    logger.info(f"\nProposing a new block with {len(mempool)} audits...")

    # Sort mempool by timestamp and req_id before taking audits
    sorted_mempool = sorted(mempool, key=lambda x: (x.timestamp, x.req_id))
    audits_to_include = sorted_mempool[:MAX_BLOCK_SIZE]
    
    previous_block_hash = confirmed_blocks.get(current_block_number - 1, block_chain_pb2.Block()).hash or "genesis"
    merkle_root = generate_merkle_root(audits_to_include)
    
    # Serialize audits for hash calculation
    audits_string = "".join([get_audit_json(audit) for audit in audits_to_include])
    
    # Calculate block hash
    data = f"{current_block_number}{previous_block_hash}{merkle_root}{audits_string}"
    block_hash = calculate_hash(data.encode())

    block = block_chain_pb2.Block(
        id=current_block_number,
        hash=block_hash,
        previous_hash=previous_block_hash,
        merkle_root=merkle_root,
        audits=audits_to_include
    )

    logger.info(f"Block {current_block_number} Proposed with {len(audits_to_include)} audits")
    return block

def send_heartbeat_to_neighbors():
    """Send heartbeat to all neighbor nodes"""
    for neighbor in NEIGHBOR_NODES:
        try:
            channel = grpc.insecure_channel(neighbor)
            stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
            
            # Create heartbeat request
            request = block_chain_pb2.HeartbeatRequest(
                from_address="Yash@" + NODE_ADDRESS,
                current_leader_address=NODE_ADDRESS if is_leader() else "",
                latest_block_id=current_block_number,
                mem_pool_size=len(mempool)
            )
            
            response = stub.SendHeartbeat(request)
            # if response.status == "success":
            #     logger.info(f"Successfully sent heartbeat to {neighbor}")
            # else:
            #     logger.warning(f"Failed to send heartbeat to {neighbor}: {response.error_message}")
                
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                logger.warning(f"Node {neighbor} is currently unavailable")
            else:
                logger.error(f"Failed to send heartbeat to {neighbor}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error sending heartbeat to {neighbor}: {e}")

def heartbeat_loop():
    """Loop that periodically sends heartbeats to neighbors"""
    while True:
        send_heartbeat_to_neighbors()
        time.sleep(10)

class BlockChainServiceServicer(block_chain_pb2_grpc.BlockChainServiceServicer):
    def WhisperAuditRequest(self, request, context):
        try:
            if not verify_audit(request):
                return block_chain_pb2.WhisperResponse(
                    status="failure", 
                    error_message="Signature verification failed"
                )

            if request not in mempool:
                mempool.append(request)
                logger.info(f"Audit {request.req_id} added to mempool")
                # Don't whisper when receiving from another node
                return block_chain_pb2.WhisperResponse(status="success")
            else:
                logger.info(f"Audit {request.req_id} already in mempool")
                return block_chain_pb2.WhisperResponse(status="success")

        except Exception as e:
            logger.error(f"Error processing audit {request.req_id}: {e}")
            return block_chain_pb2.WhisperResponse(
                status="failure", 
                error_message=str(e)
            )

    def ProposeBlock(self, request, context):
        try:
            block = request
            logger.info(f"Voting on block {block.id}")
            
            # Verify previous block hash and merkle root
            if not verify_block(block):
                logger.error(f"Block {block.id} failed verification")
                return block_chain_pb2.BlockVoteResponse(
                    vote=False,
                    status="failure",
                    error_message="Block verification failed"
                )
            
            # Verify all audit signatures in the block
            for audit in block.audits:
                if not verify_audit(audit):
                    logger.error(f"Audit {audit.req_id} in block {block.id} failed signature verification")
                    return block_chain_pb2.BlockVoteResponse(
                        vote=False,
                        status="failure",
                        error_message=f"Audit {audit.req_id} signature verification failed"
                    )
            
            logger.info(f"Block {block.id} passed all verifications")
            
            return block_chain_pb2.BlockVoteResponse(
                vote=True,
                status="success"
            )
            
        except Exception as e:
            logger.error(f"Error processing block proposal: {e}")
            return block_chain_pb2.BlockVoteResponse(
                vote=False,
                status="failure",
                error_message=str(e)
            )

    def CommitBlock(self, request, context):
        """Handle commit request from leader"""
        try:
            global current_block_number
            block = request
            logger.info(f"Received commit request for block {block.id}")
            
            # Remove audits from mempool that are in this block
            for audit in block.audits:
                if audit in mempool:
                    mempool.remove(audit)
                    logger.info(f"Removed audit {audit.req_id} from mempool")
            
            # Since we already voted yes on this block, we can commit it directly
            confirmed_blocks[block.id] = block
            save_block_to_disk(block)
            current_block_number = len(confirmed_blocks) - 1
            logger.info(f"Successfully committed block {block.id}")
            return block_chain_pb2.BlockCommitResponse(
                status="success"
            )
            
        except Exception as e:
            logger.error(f"Error processing commit request: {e}")
            return block_chain_pb2.BlockCommitResponse(
                status="failure",
                error_message=str(e)
            )

    def SendHeartbeat(self, request, context):
        """Handle heartbeat request from other nodes"""
        try:
            logger.info(f"Received heartbeat from {request.from_address}")
            logger.info(f"Current block number: {request.latest_block_id}")
            logger.info(f"Mempool size: {request.mem_pool_size}")
            
            return block_chain_pb2.HeartbeatResponse(
                status="success"
            )
            
        except Exception as e:
            logger.error(f"Error processing heartbeat: {e}")
            return block_chain_pb2.HeartbeatResponse(
                status="failure",
                error_message=str(e)
            )

class FileAuditServiceServicer(file_audit_pb2_grpc.FileAuditServiceServicer):
    def SubmitAudit(self, request, context):
        try:
            if not verify_audit(request):
                return file_audit_pb2.FileAuditResponse(
                    req_id=request.req_id,
                    status="failure",
                    error_message="Signature verification failed"
                )

            if request not in mempool:
                mempool.append(request)
                logger.info(f"Audit {request.req_id} added to mempool")
                
                # Only whisper when the request comes from SubmitAudit
                whisper_to_neighbors(request)
                
                return file_audit_pb2.FileAuditResponse(
                    req_id=request.req_id,
                    status="success"
                )
            else:
                logger.info(f"Audit {request.req_id} already in mempool")
                return file_audit_pb2.FileAuditResponse(
                    req_id=request.req_id,
                    status="success"
                )

        except Exception as e:
            logger.error(f"Error processing audit {request.req_id}: {e}")
            return file_audit_pb2.FileAuditResponse(
                req_id=request.req_id,
                status="failure",
                error_message=str(e)
            )

def proposer_loop():
    """Loop that periodically checks if we should propose a block"""
    while True:
        time.sleep(5)  # Check more frequently but only propose if conditions are met
        if is_leader() and len(mempool) >= MIN_MEMPOOL_SIZE:
            proposal = build_block()
            if proposal:
                broadcast_proposal(proposal)
        else:
            logger.debug(f"Not proposing block: is_leader={is_leader()}, mempool_size={len(mempool)}, current_block={current_block_number}")

def serve():
    global current_block_number
    
    # Load last block number
    current_block_number = load_last_block()
    logger.info(f"Starting from block {current_block_number}")
    
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    
    block_chain_pb2_grpc.add_BlockChainServiceServicer_to_server(
        BlockChainServiceServicer(), 
        server
    )
    file_audit_pb2_grpc.add_FileAuditServiceServicer_to_server(
        FileAuditServiceServicer(),
        server
    )
    
    # Extract port from NODE_ADDRESS
    port = NODE_ADDRESS.split(":")[1]
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    logger.info(f"Full Node running on {NODE_ADDRESS}...")

    # Start both the proposer and heartbeat loops
    threading.Thread(target=proposer_loop, daemon=True).start()
    threading.Thread(target=heartbeat_loop, daemon=True).start()

    server.wait_for_termination()

if __name__ == "__main__":
    serve()
