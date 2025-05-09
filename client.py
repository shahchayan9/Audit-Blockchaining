# client.py
import time
import grpc
import common_pb2
import file_audit_pb2_grpc
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Load private key for signing
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Load public key for proto
with open("public_key.pem", "rb") as f:
    public_key_str = f.read().decode()

# Prepare audit request
file_audit = common_pb2.FileAudit(
    req_id="req-001",
    file_info=common_pb2.FileInfo(file_id="123", file_name="report.txt"),
    user_info=common_pb2.UserInfo(user_id="1000", user_name="chayan"),
    access_type=common_pb2.READ,
    timestamp=int(time.time())
)

# Sign the message
msg_bytes = file_audit.SerializeToString()
signature = private_key.sign(
    msg_bytes,
    padding.PKCS1v15(),
    hashes.SHA256()
)

file_audit.signature = signature.hex()
file_audit.public_key = public_key_str

# gRPC call to full node
channel = grpc.insecure_channel("localhost:50051")
stub = file_audit_pb2_grpc.FileAuditServiceStub(channel)

response = stub.SubmitAudit(file_audit)
print("Response from Full Node:", response)
