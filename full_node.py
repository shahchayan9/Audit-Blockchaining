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

# AI Generated Code for file formatting, logging, and try-catch blocks.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

mempool: List[common_pb2.FileAudit] = []
confirmed_blocks: Dict[int, block_chain_pb2.Block] = {}
current_block_number = -1
votes_received: Dict[str, List[block_chain_pb2.BlockVoteResponse]] = {}
current_leader = None
server_health: Dict[str, float] = {}
server_heartbeat_data: Dict[str, Dict] = {}

HEARTBEAT_TIMEOUT = 15
ENABLE_BLOCK_RECOVERY = True
ELECTION_ENABLED = True
NEIGHBOR_NODES = [
    "169.254.52.33:50052",
    "169.254.159.92:50053",
    "169.254.183.161:50051",
    "169.254.181.125:50051",
    "169.254.81.113:50051",
    "169.254.55.120:50051",
    "169.254.10.111:50051",
    "169.254.128.210:50052",
    "169.254.244.174:50052"
]
BLOCKS_DIR = "blocks"
MAX_BLOCK_SIZE = 100
MIN_MEMPOOL_SIZE = 3
NODE_ADDRESS = "169.254.13.100:50051"

# AI Generated Code for ensuring blocks directory exists
def ensure_blocks_directory():
    if not os.path.exists(BLOCKS_DIR):
        os.makedirs(BLOCKS_DIR)
        logger.info(f"Created blocks directory at {BLOCKS_DIR}")

def calculate_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()    
    
def is_leader() -> bool:
    global current_leader
    return NODE_ADDRESS == current_leader

def get_audit_json(audit: common_pb2.FileAudit) -> str:
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
    try:
        public_key = serialization.load_pem_public_key(
            audit.public_key.encode(), 
            backend=default_backend()
        )

        data_to_verify = get_audit_json(audit).encode('utf-8')
        signature_bytes = base64.b64decode(audit.signature)

        public_key.verify(
            signature_bytes,
            data_to_verify,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
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
    ensure_blocks_directory()
    filename = os.path.join(BLOCKS_DIR, f"block_{block.id}.json")
    
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

# AI Generated Code for loading last block number
def load_last_block() -> int:
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
    ensure_blocks_directory()
    filename = os.path.join(BLOCKS_DIR, f"block_{block_id}.json")
    
    if not os.path.exists(filename):
        logger.warning(f"Block {block_id} not found on disk")
        return None
        
    try:
        with open(filename, 'r') as f:
            block_dict = json.load(f)
            
        block = block_chain_pb2.Block(
            id=block_dict["id"],
            hash=block_dict["hash"],
            previous_hash=block_dict["previous_hash"],
            merkle_root=block_dict["merkle_root"]
        )
        
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

# AI Generated Code for generating merkle root as per discussion with the rest of the class
def generate_merkle_root(audits: List[common_pb2.FileAudit]) -> str:
    if not audits:
        return ""
    
    hashes = []
    for audit in audits:
        hashes.append(calculate_hash(get_audit_json(audit).encode()))
    
    while len(hashes) > 1:
        new_hashes = []
        for i in range(0, len(hashes), 2):
            left = hashes[i]
            right = hashes[i + 1] if i + 1 < len(hashes) else left
            new_hashes.append(calculate_hash((left + right).encode()))
        hashes = new_hashes
    
    return hashes[0] if hashes else ""

def verify_block(block: block_chain_pb2.Block) -> bool:
    try:
        if block.id > 1:
            prev_block = confirmed_blocks.get(block.id - 1)
            if not prev_block or prev_block.hash != block.previous_hash:
                logger.error("Invalid previous block hash")
                return False
        
        calculated_root = generate_merkle_root(block.audits)
        if calculated_root != block.merkle_root:
            logger.error("Invalid Merkle root")
            return False
        
        audits_string = "".join([get_audit_json(audit) for audit in block.audits])
        block_hash = calculate_hash(f"{block.id}{block.previous_hash}{block.merkle_root}{audits_string}".encode())
        if block_hash != block.hash:
            logger.error("Invalid block hash")
            return False
            
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
    global current_block_number
    
    if not NEIGHBOR_NODES:
        logger.info("No neighbors - auto confirming block")
        confirmed_blocks[block.id] = block
        save_block_to_disk(block)
        current_block_number = len(confirmed_blocks) - 1
        return

    votes_received[str(block.id)] = []
    
    for neighbor in NEIGHBOR_NODES:
        try:
            channel = grpc.insecure_channel(neighbor)
            stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
            response = stub.ProposeBlock(block)
            logger.info(f"Proposal sent to {neighbor}: {response.status}")
            
            if response.status == "success" and response.vote:
                votes_received[str(block.id)].append(response)
                logger.info(f"Received yes vote from {neighbor} for block {block.id}")
                
        except Exception as e:
            logger.error(f"Failed to send proposal to {neighbor}: {e}")
    
    if len(votes_received[str(block.id)]) == len(NEIGHBOR_NODES):
        logger.info(f"Block {block.id} received full consensus: ({len(votes_received[str(block.id)])} votes)")
        
        confirmed_blocks[block.id] = block
        save_block_to_disk(block)
        current_block_number = len(confirmed_blocks) - 1
        
        for audit in block.audits:
            if audit in mempool:
                mempool.remove(audit)
                logger.info(f"Removed audit {audit.req_id} from mempool")
        
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
    
    del votes_received[str(block.id)]

def build_block() -> Optional[block_chain_pb2.Block]:
    global mempool, current_block_number
    
    if not is_leader():
        logger.info(f"Not the leader for block {current_block_number}, skipping proposal")
        return None
        
    if len(mempool) < MIN_MEMPOOL_SIZE:
        logger.info(f"Mempool size {len(mempool)} is below threshold {MIN_MEMPOOL_SIZE}")
        return None

    if str(current_block_number) in votes_received and get_healthy_neighbors():
        logger.info(f"Already waiting for votes on block {current_block_number}")
        return None

    logger.info(f"\nProposing a new block with {len(mempool)} audits...")

    sorted_mempool = sorted(mempool, key=lambda x: (x.timestamp, x.req_id))
    audits_to_include = sorted_mempool[:MAX_BLOCK_SIZE]
    
    previous_block_hash = confirmed_blocks.get(current_block_number, block_chain_pb2.Block()).hash or "genesis"
    merkle_root = generate_merkle_root(audits_to_include)
    
    audits_string = "".join([get_audit_json(audit) for audit in audits_to_include])
    
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
    for neighbor in NEIGHBOR_NODES:
        try:
            channel = grpc.insecure_channel(neighbor)
            stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
            
            request = block_chain_pb2.HeartbeatRequest(
                from_address=NODE_ADDRESS,
                current_leader_address=current_leader,
                latest_block_id=current_block_number,
                mem_pool_size=len(mempool)
            )
            
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
    global FIRST_RUN
    while True:
        logger.info(f"Sending heartbeat to neighbors: {NEIGHBOR_NODES}")
        send_heartbeat_to_neighbors()
        time.sleep(10)
        check_leader_health()
        
        if ENABLE_BLOCK_RECOVERY and ((current_leader is not None and is_server_healthy(current_leader)) or current_leader == NODE_ADDRESS):
            leader_data = server_heartbeat_data.get(current_leader, {})
            leader_block_id = leader_data.get('block_id', -1)
            
            if leader_block_id > current_block_number:
                logger.info(f"We are behind the leader (our block: {current_block_number}, leader block: {leader_block_id})")
                threading.Thread(target=recover_blocks_from_leader, daemon=True).start()

def is_server_healthy(address: str) -> bool:
    if address not in server_health:
        return False
    
    return (time.time() - server_health[address]) < HEARTBEAT_TIMEOUT

def get_healthy_neighbors() -> List[str]:
    return [node for node in NEIGHBOR_NODES if is_server_healthy(node)]

def trigger_election():
    global current_leader
    
    logger.info("Triggering new election")
    max_votes = len(get_healthy_neighbors()) + 1
    if max_votes == 1:
        logger.info("No healthy neighbors, skipping election")
        return
    
    votes_needed = max_votes // 2 + 1
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
    
    if votes_received >= votes_needed:
        logger.info(f"Won election with {votes_received}/{max_votes} votes")
        current_leader = NODE_ADDRESS
        notify_leadership()
    else:
        logger.info(f"Lost election with {votes_received}/{max_votes} votes")

def notify_leadership():
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
    global current_leader
    if not ELECTION_ENABLED:
        return
        
    if current_leader is None or (current_leader != NODE_ADDRESS and not is_server_healthy(current_leader)):
        logger.warning(f"No current leader or current leader {current_leader} is unhealthy, triggering re-election")
        trigger_election()

def update_server_heartbeat_data(address: str, block_id: int, mempool_size: int):
    global server_heartbeat_data
    server_heartbeat_data[address] = {
        'block_id': block_id,
        'mempool_size': mempool_size,
        'last_update': time.time()
    }

# AI Generated Code for comparing server metrics for election
def compare_server_metrics(candidate_address: str) -> bool:
    global server_heartbeat_data, NODE_ADDRESS
    
    our_metrics = server_heartbeat_data.get(NODE_ADDRESS, {
        'block_id': current_block_number,
        'mempool_size': len(mempool)
    })
    
    candidate_metrics = server_heartbeat_data.get(candidate_address, {
        'block_id': 0,
        'mempool_size': 0
    })
    
    if candidate_metrics['block_id'] > our_metrics['block_id']:
        return True
    elif candidate_metrics['block_id'] < our_metrics['block_id']:
        return False
    
    if candidate_metrics['mempool_size'] > our_metrics['mempool_size']:
        return True
    elif candidate_metrics['mempool_size'] < our_metrics['mempool_size']:
        return False
    
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
        try:
            global current_block_number
            block = request
            logger.info(f"Received commit request for block {block.id}")
            
            for audit in block.audits:
                if audit in mempool:
                    mempool.remove(audit)
                    logger.info(f"Removed audit {audit.req_id} from mempool")
            
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
        try:
            global server_health, server_heartbeat_data, current_leader
            logger.info(f"Received heartbeat from {request.from_address} [block_id: {request.latest_block_id}, leader: {request.current_leader_address}, mempool_size: {request.mem_pool_size}]")
            
            server_health[request.from_address] = time.time()
            
            update_server_heartbeat_data(
                request.from_address,
                request.latest_block_id,
                request.mem_pool_size
            )
            
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
        try:
            global current_leader
            logger.info(f"Received election trigger from {request.address}")
            
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
        try:
            global current_leader
            logger.info(f"Received leadership notification from {request.address}")
            
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
        try:
            block_id = request.id
            logger.info(f"Received GetBlock request for block {block_id}")
            
            if block_id in confirmed_blocks:
                logger.info(f"Found block {block_id} in memory")
                return block_chain_pb2.GetBlockResponse(
                    block=confirmed_blocks[block_id],
                    status="success"
                )
            
            block = load_block_from_disk(block_id)
            if block:
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
    while True:
        time.sleep(5)
        if is_leader() and len(mempool) >= MIN_MEMPOOL_SIZE:
            proposal = build_block()
            if proposal:
                broadcast_proposal(proposal)
        else:
            logger.debug(f"Not proposing block: is_leader={is_leader()}, mempool_size={len(mempool)}, current_block={current_block_number}")

def serve():
    global current_block_number
    
    current_block_number = load_last_block()
    logger.info(f"Starting from block {current_block_number}")
    
    for block_id in range(current_block_number + 1):
        block = load_block_from_disk(block_id)
        if block:
            confirmed_blocks[block_id] = block
            logger.info(f"Loaded block {block_id} into memory")
    
    port = 50051
    
    # AI Generated Code for creating/starting gRPC server & adding servicers
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    block_chain_pb2_grpc.add_BlockChainServiceServicer_to_server(
        BlockChainServiceServicer(), 
        server
    )

    file_audit_pb2_grpc.add_FileAuditServiceServicer_to_server(
        FileAuditServiceServicer(),
        server
    )
    
    server.add_insecure_port(f"0.0.0.0:{port}")
    server.start()
    
    threading.Thread(target=proposer_loop, daemon=True).start()
    threading.Thread(target=heartbeat_loop, daemon=True).start()

    server.wait_for_termination()

def recover_blocks_from_leader():
    global current_block_number, confirmed_blocks
    
    if not current_leader:
        logger.warning("No current leader, cannot recover blocks")
        return
        
    try:
        channel = grpc.insecure_channel(current_leader)
        stub = block_chain_pb2_grpc.BlockChainServiceStub(channel)
        
        leader_data = server_heartbeat_data.get(current_leader, {})
        leader_block_id = leader_data.get('block_id', -1)
        
        if leader_block_id <= current_block_number:
            logger.info("No new blocks to recover")
            return
            
        for block_id in range(current_block_number + 1, leader_block_id + 1):
            request = block_chain_pb2.GetBlockRequest(id=block_id)
            response = stub.GetBlock(request)
            
            if response.status == "success":
                block = response.block
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