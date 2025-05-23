# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

import common_pb2 as common__pb2
import file_audit_pb2 as file__audit__pb2


class FileAuditServiceStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.SubmitAudit = channel.unary_unary(
                '/fileaudit.FileAuditService/SubmitAudit',
                request_serializer=common__pb2.FileAudit.SerializeToString,
                response_deserializer=file__audit__pb2.FileAuditResponse.FromString,
                )


class FileAuditServiceServicer(object):
    """Missing associated documentation comment in .proto file."""

    def SubmitAudit(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_FileAuditServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'SubmitAudit': grpc.unary_unary_rpc_method_handler(
                    servicer.SubmitAudit,
                    request_deserializer=common__pb2.FileAudit.FromString,
                    response_serializer=file__audit__pb2.FileAuditResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'fileaudit.FileAuditService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class FileAuditService(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def SubmitAudit(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/fileaudit.FileAuditService/SubmitAudit',
            common__pb2.FileAudit.SerializeToString,
            file__audit__pb2.FileAuditResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
