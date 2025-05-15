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
import traceback

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
current_block_number = -1
votes_received: Dict[str, List[block_chain_pb2.BlockVoteResponse]] = {}
current_leader = None  # Track the current leader's address
server_health: Dict[str, float] = {}  # Track last heartbeat time for each server
server_heartbeat_data: Dict[str, Dict] = {}  # Track heartbeat data for each server

HEARTBEAT_TIMEOUT = 15  # Seconds before marking a server as unhealthy
ENABLE_BLOCK_RECOVERY = False  # Flag to control block recovery functionality
ELECTION_ENABLED = False  # Flag to control election functionality
NEIGHBOR_NODES = [
    "169.254.27.203:50052",   # sameer
    # "169.254.183.161:50051",  # harsha
    # "169.254.55.120:50051",   # brandon
    "169.254.159.92:50053",   # suriya
    # "169.254.45.104:50051",   # serhat
    "169.254.153.82:50051"   # jayasurya
    # "169.254.137.247:50051",  # ronak
]
BLOCKS_DIR = "blocks"
MAX_BLOCK_SIZE = 100  # Maximum number of audits per block
MIN_MEMPOOL_SIZE = 3  # Minimum number of audits required to propose a block
NODE_ADDRESS = "169.254.13.100:50051"  # Your WSL IP address
FIRST_RUN = True

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
        logger.info("No existing blocks found, starting from block -1")
        return -1
    
    block_numbers = [int(f.split("_")[1].split(".")[0]) for f in block_files]
    last_block = max(block_numbers)
    logger.info(f"Loaded last block number: {last_block}")
    return last_block

def load_block_from_disk(block_id: int) -> Optional[block_chain_pb2.Block]:
    """Load a specific block from disk by ID"""
    ensure_blocks_directory()
    filename = os.path.join(BLOCKS_DIR, f"block_{block_id}.json")
    
    if not os.path.exists(filename):
        logger.warning(f"Block {block_id} not found on disk")
        return None
        
    try:
        with open(filename, 'r') as f:
            block_dict = json.load(f)
            
        # Convert dictionary back to protobuf Block
        block = block_chain_pb2.Block(
            id=block_dict["id"],
            hash=block_dict["hash"],
            previous_hash=block_dict["previous_hash"],
            merkle_root=block_dict["merkle_root"]
        )
        
        # Convert audits back to protobuf FileAudit objects
        for audit_dict in block_dict["audits"]:
            audit = common_pb2.FileAudit(
                req_id=audit_dict["req_id"],
                file_info=common_pb2.FileInfo(
                    file_id=audit_dict["file_info"]["file_id"],
                    file_name=audit_dict["file_info"]["file_name"]
                ),
                user_info=common_pb2.UserInfo(
                    user_id=audit_dict["user_info"]["user_id"],
                    user_name=audit_dict["user_info"]["user_name"]
                ),
                access_type=audit_dict["access_type"],
                timestamp=audit_dict["timestamp"],
                signature=audit_dict["signature"],
                public_key=audit_dict["public_key"]
            )
            block.audits.append(audit)
            
        logger.info(f"Successfully loaded block {block_id} from disk")
        return block
        
    except Exception as e:
        logger.error(f"Error loading block {block_id} from disk: {e}")
        return None

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
        if calculated_root != block.merkle_root:
            logger.error("Invalid Merkle root")
            return False
        
        # Verify block hash
        audits_string = "".join([get_audit_json(audit) for audit in block.audits])
        block_hash = calculate_hash(f"{block.id}{block.previous_hash}{block.merkle_root}{audits_string}".encode())
        if block_hash != block.hash:
            logger.error("Invalid block hash")
            return False
            
        # Verify all audit signatures in the block
        for audit in block.audits:
            if not verify_audit(audit):
                logger.error(f"Audit {audit.req_id} in block {block.id} failed signature verification")
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
        save_block_to_disk(block)
        current_block_number = len(confirmed_blocks) - 1  # Update current_block_number
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
        current_block_number = len(confirmed_blocks) - 1
        
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
    if str(current_block_number) in votes_received and get_healthy_neighbors():  # Only check if we have healthy neighbors
        logger.info(f"Already waiting for votes on block {current_block_number}")
        return None

    logger.info(f"\nProposing a new block with {len(mempool)} audits...")

    # Sort mempool by timestamp and req_id before taking audits
    sorted_mempool = sorted(mempool, key=lambda x: (x.timestamp, x.req_id))
    audits_to_include = sorted_mempool[:MAX_BLOCK_SIZE]
    
    previous_block_hash = confirmed_blocks.get(current_block_number, block_chain_pb2.Block()).hash or "genesis"
    merkle_root = generate_merkle_root(audits_to_include)
    
    # Serialize audits for hash calculation
    audits_string = "".join([get_audit_json(audit) for audit in audits_to_include])
    
    # Calculate block hash
    data = f"{current_block_number + 1}{previous_block_hash}{merkle_root}{audits_string}"
    logger.info(f"Data: {data}")
    block_hash = calculate_hash(data.encode())

    block = block_chain_pb2.Block(
        id=current_block_number + 1,
        hash=block_hash,
        previous_hash=previous_block_hash,
        merkle_root=merkle_root,
        audits=audits_to_include
    )

    logger.info(f"Block {current_block_number + 1} Proposed with {len(audits_to_include)} audits")
    return block

def send_heartbeat_to_neighbors():
    """Send heartbeat to all neighbor nodes"""
    for neighbor in NEIGHBOR_NODES:
        try:
            channel = grpc.insecure_channel(neighbor)
            stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
            
            # Create heartbeat request
            request = block_chain_pb2.HeartbeatRequest(
                from_address=NODE_ADDRESS,
                current_leader_address=current_leader,
                latest_block_id=current_block_number,
                mem_pool_size=len(mempool)
            )
            
            # Set a timeout for the heartbeat request
            response = stub.SendHeartbeat(request)
            if response.status == "success":
                logger.info(f"Successfully sent heartbeat to {neighbor}")
            else:
                logger.warning(f"Failed to send heartbeat to {neighbor}: {response.error_message}")
                
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                logger.warning(f"Node {neighbor} is currently unavailable")
            elif e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
                logger.warning(f"Timeout while sending heartbeat to {neighbor}")
            else:
                logger.error(f"gRPC error sending heartbeat to {neighbor}: {e.code()} - {e.details()}")
        except Exception as e:
            logger.error(f"Unexpected error sending heartbeat to {neighbor}: {e}")
            logger.error(f"Error type: {type(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")

def heartbeat_loop():
    """Loop that periodically sends heartbeats to neighbors and checks leader health"""
    global FIRST_RUN
    while True:
        logger.info(f"Sending heartbeat to neighbors: {NEIGHBOR_NODES}")
        send_heartbeat_to_neighbors()
        time.sleep(10)
        check_leader_health()  # Check leader health after sending heartbeats
        
        # Check if we need to recover blocks from leader
        if ENABLE_BLOCK_RECOVERY and ((current_leader is not None and is_server_healthy(current_leader)) or current_leader == NODE_ADDRESS):
            leader_data = server_heartbeat_data.get(current_leader, {})
            leader_block_id = leader_data.get('block_id', -1)
            
            if leader_block_id > current_block_number:
                logger.info(f"We are behind the leader (our block: {current_block_number}, leader block: {leader_block_id})")
                # Start block recovery in a separate thread
                threading.Thread(target=recover_blocks_from_leader, daemon=True).start()

def is_server_healthy(address: str) -> bool:
    """Check if a server is healthy based on its last heartbeat"""
    if address not in server_health:
        return False
    
    return (time.time() - server_health[address]) < HEARTBEAT_TIMEOUT

def get_healthy_neighbors() -> List[str]:
    """Get list of healthy neighbor nodes"""
    return [node for node in NEIGHBOR_NODES if is_server_healthy(node)]

def trigger_election():
    """Trigger a new election by sending election requests to all neighbors"""
    global current_leader
    
    logger.info("Triggering new election")
    max_votes = len(get_healthy_neighbors()) + 1
    if max_votes == 1:
        logger.info("No healthy neighbors, skipping election")
        return
    
    votes_needed = max_votes // 2 + 1  # Majority of nodes
    votes_received = 1
    
    for neighbor in get_healthy_neighbors():
        try:
            channel = grpc.insecure_channel(neighbor)
            stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
            
            request = block_chain_pb2.TriggerElectionRequest(
                address=NODE_ADDRESS
            )
            
            response = stub.TriggerElection(request)
            if response.vote:
                votes_received += 1
                logger.info(f"Received yes vote from {neighbor}")
            else:
                logger.info(f"Received no vote from {neighbor}")
        
        except Exception as e:
            logger.error(f"Failed to request vote from {neighbor}: {e}")
    
    # If we got majority votes, notify all nodes of our leadership
    if votes_received >= votes_needed:
        logger.info(f"Won election with {votes_received}/{max_votes} votes")
        current_leader = NODE_ADDRESS
        notify_leadership()
    else:
        logger.info(f"Lost election with {votes_received}/{max_votes} votes")

def notify_leadership():
    """Notify all neighbors of our leadership"""
    global current_leader
    current_leader = NODE_ADDRESS
    
    for neighbor in NEIGHBOR_NODES:
        try:
            channel = grpc.insecure_channel(neighbor)
            stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
            
            request = block_chain_pb2.NotifyLeadershipRequest(
                address=NODE_ADDRESS
            )
            
            response = stub.NotifyLeadership(request)
            logger.info(f"Leadership notification sent to {neighbor}: {response.status}")
            
        except Exception as e:
            logger.error(f"Failed to notify leadership to {neighbor}: {e}")

def check_leader_health():
    """Check if there is no current leader or if the current leader is unhealthy and trigger re-election if needed"""
    global current_leader
    if not ELECTION_ENABLED:
        return
        
    if current_leader is None or (current_leader != NODE_ADDRESS and not is_server_healthy(current_leader)):
        logger.warning(f"No current leader or current leader {current_leader} is unhealthy, triggering re-election")
        trigger_election()

def update_server_heartbeat_data(address: str, block_id: int, mempool_size: int):
    """Update heartbeat data for a server"""
    global server_heartbeat_data
    server_heartbeat_data[address] = {
        'block_id': block_id,
        'mempool_size': mempool_size,
        'last_update': time.time()
    }

def compare_server_metrics(candidate_address: str) -> bool:
    """Compare server metrics to determine if candidate should be leader"""
    global server_heartbeat_data, NODE_ADDRESS
    
    # Get our metrics
    our_metrics = server_heartbeat_data.get(NODE_ADDRESS, {
        'block_id': current_block_number,
        'mempool_size': len(mempool)
    })
    
    # Get candidate metrics
    candidate_metrics = server_heartbeat_data.get(candidate_address, {
        'block_id': 0,
        'mempool_size': 0
    })
    
    # logger.info(f"Candidate metrics: {candidate_metrics}")
    # logger.info(f"Our metrics: {our_metrics}")

    # Compare block IDs first
    if candidate_metrics['block_id'] > our_metrics['block_id']:
        return True
    elif candidate_metrics['block_id'] < our_metrics['block_id']:
        return False
    
    # If block IDs are equal, compare mempool sizes
    if candidate_metrics['mempool_size'] > our_metrics['mempool_size']:
        return True
    elif candidate_metrics['mempool_size'] < our_metrics['mempool_size']:
        return False
    
    # If both metrics are equal, compare IP addresses
    return candidate_address > NODE_ADDRESS

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
            
            # Verify block (now includes audit verification)
            if not verify_block(block):
                logger.error(f"Block {block.id} failed verification")
                return block_chain_pb2.BlockVoteResponse(
                    vote=False,
                    status="failure",
                    error_message="Block verification failed"
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
            global server_health, server_heartbeat_data, current_leader
            logger.info(f"Received heartbeat from {request.from_address} [block_id: {request.latest_block_id}, leader: {request.current_leader_address}, mempool_size: {request.mem_pool_size}]")
            
            # Update server health status
            server_health[request.from_address] = time.time()
            
            # Update heartbeat data
            update_server_heartbeat_data(
                request.from_address,
                request.latest_block_id,
                request.mem_pool_size
            )
            
            # Only update current_leader if it's None
            if current_leader is None and request.current_leader_address:
                current_leader = request.current_leader_address
            
            return block_chain_pb2.HeartbeatResponse(
                status="success"
            )
            
        except Exception as e:
            logger.error(f"Error processing heartbeat: {e}")
            return block_chain_pb2.HeartbeatResponse(
                status="failure",
                error_message=str(e)
            )

    def TriggerElection(self, request, context):
        """Handle election trigger request from a candidate node"""
        try:
            global current_leader
            logger.info(f"Received election trigger from {request.address}")
            
            # Compare server metrics to decide vote
            should_vote_yes = compare_server_metrics(request.address)
            
            if should_vote_yes:
                logger.info(f"Voting yes for {request.address} based on metrics")
                return block_chain_pb2.TriggerElectionResponse(
                    vote=True,
                    status="success"
                )
            else:
                logger.info(f"Voting no for {request.address} based on metrics")
                return block_chain_pb2.TriggerElectionResponse(
                    vote=False,
                    status="success",
                    error_message="Better candidate available"
                )
            
        except Exception as e:
            logger.error(f"Error processing election trigger: {e}")
            return block_chain_pb2.TriggerElectionResponse(
                vote=False,
                status="failure",
                error_message=str(e)
            )

    def NotifyLeadership(self, request, context):
        """Handle leadership notification from the newly elected leader"""
        try:
            global current_leader
            logger.info(f"Received leadership notification from {request.address}")
            
            # Update our knowledge of the current leader
            current_leader = request.address
            logger.info(f"Updated current leader to {current_leader}")
            
            return block_chain_pb2.NotifyLeadershipResponse(
                status="success"
            )
            
        except Exception as e:
            logger.error(f"Error processing leadership notification: {e}")
            return block_chain_pb2.NotifyLeadershipResponse(
                status="failure",
                error_message=str(e)
            )

    def GetBlock(self, request, context):
        """Handle GetBlock request from other nodes"""
        try:
            block_id = request.id
            logger.info(f"Received GetBlock request for block {block_id}")
            
            # First check if we have the block in memory
            if block_id in confirmed_blocks:
                logger.info(f"Found block {block_id} in memory")
                return block_chain_pb2.GetBlockResponse(
                    block=confirmed_blocks[block_id],
                    status="success"
                )
            
            # If not in memory, try to load from disk
            block = load_block_from_disk(block_id)
            if block:
                # Cache the block in memory
                confirmed_blocks[block_id] = block
                logger.info(f"Found block {block_id} on disk")
                return block_chain_pb2.GetBlockResponse(
                    block=block,
                    status="success"
                )
            
            logger.warning(f"Block {block_id} not found")
            return block_chain_pb2.GetBlockResponse(
                status="failure",
                error_message=f"Block {block_id} not found"
            )
            
        except Exception as e:
            logger.error(f"Error processing GetBlock request: {e}")
            return block_chain_pb2.GetBlockResponse(
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
    
    # Load all existing blocks into memory
    for block_id in range(current_block_number + 1):
        block = load_block_from_disk(block_id)
        if block:
            confirmed_blocks[block_id] = block
            logger.info(f"Loaded block {block_id} into memory")
    
    # Extract port from NODE_ADDRESS
    port = 50051
    
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    
    block_chain_pb2_grpc.add_BlockChainServiceServicer_to_server(
        BlockChainServiceServicer(), 
        server
    )
    file_audit_pb2_grpc.add_FileAuditServiceServicer_to_server(
        FileAuditServiceServicer(),
        server
    )
    
    # Log server binding information
    server.add_insecure_port(f"0.0.0.0:{port}")  # Bind to all IPv4 interfaces
    server.start()
    
    # Start both the proposer and heartbeat loops
    threading.Thread(target=proposer_loop, daemon=True).start()
    threading.Thread(target=heartbeat_loop, daemon=True).start()

    server.wait_for_termination()

def recover_blocks_from_leader():
    """Recover missing blocks from the leader"""
    global current_block_number, confirmed_blocks
    
    if not current_leader:
        logger.warning("No current leader, cannot recover blocks")
        return
        
    try:
        channel = grpc.insecure_channel(current_leader)
        stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
        
        # Get leader's latest block ID from our stored data
        leader_data = server_heartbeat_data.get(current_leader, {})
        leader_block_id = leader_data.get('block_id', -1)
        
        if leader_block_id <= current_block_number:
            logger.info("No new blocks to recover")
            return
            
        # Request each missing block
        for block_id in range(current_block_number + 1, leader_block_id + 1):
            request = block_chain_pb2.GetBlockRequest(id=block_id)
            response = stub.GetBlock(request)
            
            if response.status == "success":
                block = response.block
                # Verify the block before accepting it
                if verify_block(block):
                    confirmed_blocks[block_id] = block
                    save_block_to_disk(block)
                    current_block_number = block_id
                    logger.info(f"Recovered block {block_id} from leader")
                else:
                    logger.error(f"Block {block_id} failed verification")
                    break
            else:
                logger.error(f"Failed to get block {block_id} from leader: {response.error_message}")
                break
                
    except Exception as e:
        logger.error(f"Error recovering blocks from leader: {e}")

if __name__ == "__main__":
    serve()
