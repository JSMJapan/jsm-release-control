"""Root-only configured-FPM metadata producer; no remote operational entry.

Caller context must come from the protected private sandbox publisher. Syntax
validation here is not authentication of that publisher. Installation/wiring is
reviewed separately; importing this module performs no observation.
"""
import os
import pwd
import secrets
import socket
import struct
import sys
import time

from test_db_runtime_protocol import VERSION, Rejected, Wire, context_digest
from test_db_runtime_fastcgi import FastCGI
from test_db_runtime_kernel import Kernel

STAGES=('CONTEXT','FPM_BEFORE','CHANNEL','STARTUP','LOCAL_TARGET','CONNECT','PEER_BEFORE_SQL','SELECT','PEER_AFTER_SQL','FPM_AFTER','FASTCGI_END','COMPLETE')
REASONS=('CONTEXT_REQUIRED','ROOT_LINUX_REQUIRED','FPM_REFUSED','CHANNEL_REFUSED','FRAME_REFUSED','FRAME_LIMIT',
         'DEADLINE','FASTCGI_REFUSED','STARTUP_REFUSED','CONFIG_SHAPE_REFUSED','GENERATED_CONFIG_REFUSED',
         'STARTUP_SOURCE_REFUSED','STARTUP_HOOK_REFUSED','STARTUP_CONTEXT_REFUSED','VENDOR_PROFILE_REFUSED',
         'MODEL_SOURCE_REFUSED','PROC_REFUSED','CGROUP_UNAVAILABLE','APPLICATION_REFUSED','DB_DEFINITION_REFUSED','PDO_ATTRIBUTE_REFUSED','PDO_CAPABILITY_REFUSED',
         'PDO_AUTH_REFUSED','PDO_CONNECT_REFUSED','PDO_QUERY_REFUSED','METADATA_REFUSED',
         'TARGET_REFUSED','CGROUP_REFUSED','PROCESS_REFUSED','TCP_REFUSED','DOCKER_UNCONFIRMED',
         'MYSQL_CANDIDATE_REFUSED','LOCAL_LISTENER_REFUSED','FORWARDING_UNCONFIRMED','PEER_CHANGED',
         'PHP_PEER_REFUSED','DB_PEER_REFUSED','INTERNAL_REFUSED')
FD_REASONS=tuple(role+'_'+code for role in ('DB','PHP','PROXY') for code in
    ('FD_ENTRY_LIMIT','FD_NAME_REFUSED','FD_TARGET_LIMIT','FD_DISAPPEARED','FD_ACCESS_REFUSED','FD_IO_REFUSED'))


def reason(error):
    if isinstance(error,ValueError) and error.args==('DEADLINE',):return 'DEADLINE'
    if isinstance(error,OSError):return 'PROC_REFUSED'
    return error.args[0] if type(error) is Rejected and len(error.args)==1 and error.args[0] in REASONS+FD_REASONS else 'INTERNAL_REFUSED'


def receive(wire, sequence):
    payload=wire.receive('PHP',sequence)
    if payload['stage']=='REFUSED':raise Rejected(payload['reason'])
    return payload


def closed():
    return dict(version=VERSION,status='BLOCKED',stage='CONTEXT',reason='CONTEXT_REQUIRED',
                configured_runtime='NOT_ESTABLISHED',dependency_trust='INSTALLED_VENDOR_NOT_ATTESTED',
                local_peer='NOT_ESTABLISHED',metadata=None,sql='NOT_ATTEMPTED',
                synthetic_provenance='UNKNOWN',grants='UNKNOWN',egress_isolation='UNKNOWN',
                arbitrary_request_binding='NOT_ESTABLISHED')


def dialogue(wire,kernel,worker,publisher,receipt):
    """Fixed coordinator used verbatim by runtime and synthetic peer fixtures."""
    wire.send('ROOT',0,{'stage':'HELLO','publisher_uid':publisher})
    receipt['stage']='STARTUP';proposed=receive(wire,1)
    receipt['stage']='LOCAL_TARGET'
    witness=kernel.before({key:value for key,value in proposed.items() if key!='stage'})
    wire.send('ROOT',2,{'stage':'OPEN'})
    receipt['stage']='CONNECT';receive(wire,3)
    receipt['stage']='PEER_BEFORE_SQL';peer=kernel.peer(worker,witness)
    receipt['local_peer']='OBSERVED'
    receipt['stage']='SELECT'
    # Set only once authorization is actually sent; never infer GET/query
    # success from an attempted diagnostic or a peer tuple alone.
    wire.send('ROOT',4,{'stage':'SELECT'});receipt['sql']='AUTHORIZED_NOT_CONFIRMED'
    metadata=receive(wire,5)
    if metadata.get('schema_matches') is not True:raise Rejected('METADATA_REFUSED')
    receipt['stage']='PEER_AFTER_SQL'
    if kernel.peer(worker,witness)!=peer:raise Rejected('PEER_CHANGED')
    wire.send('ROOT',6,{'stage':'RESULT','accepted':True})
    receipt['metadata']={key:value for key,value in metadata.items() if key!='stage'}
    receipt['sql']='ONE_METADATA_SELECT_OBSERVED'
    receipt['configured_runtime']='OBSERVED'


def worker_from_peer(snapshot, credentials, kernel, deadline):
    worker,uid,gid=credentials
    if (type(worker) is not int or type(uid) is not int or uid<=0 or uid==snapshot[4][0]):
        raise Rejected('FPM_REFUSED')
    matching=[(identity,ids) for pid,identity,ids in snapshot[3] if pid==worker]
    if len(matching)!=1 or matching[0][1]!=(uid,uid,uid,uid):raise Rejected('FPM_REFUSED')
    if (kernel.ns['_php_endpoint_identity'](worker,deadline)!=matching[0][0]
            or kernel.ns['_manifest_worker_uid'](worker,snapshot[4],deadline)!=matching[0][1]):
        raise Rejected('FPM_REFUSED')
    return worker


def collect(context):
    receipt=closed();listener=request=connection=None;lock=None
    try:
        context_digest(context)
        if sys.platform!='linux' or os.geteuid()!=0:raise Rejected('ROOT_LINUX_REQUIRED')
        deadline=time.monotonic()+3
        kernel=Kernel(deadline)
        receipt['stage']='FPM_BEFORE';lock=kernel.ns['_manifest_lock'](deadline);snapshot,_=kernel.fpm()
        publisher=pwd.getpwnam('jsm').pw_uid
        if not 0<publisher<=2147483647:raise Rejected('FPM_REFUSED')
        nonce,channel=secrets.token_hex(16),secrets.token_hex(16)
        digest=context_digest(context)
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        listener.bind('\0jsm-db-2760-'+channel);listener.listen(1)
        receipt['stage']='CHANNEL'
        def fpm_peer(stream):
            pid,uid,gid=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if pid!=snapshot[0]['php']['pid'] or uid!=0:raise Rejected('FPM_REFUSED')
        request=FastCGI(nonce,digest,channel,deadline,peer_check=fpm_peer)
        listener.settimeout(min(.75,max(0,deadline-time.monotonic())))
        connection,_=listener.accept()
        worker=worker_from_peer(snapshot,struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)),kernel,deadline)
        wire=Wire(connection,nonce,digest,deadline)
        dialogue(wire,kernel,worker,publisher,receipt)
        receipt['stage']='FPM_AFTER'
        after,_=kernel.fpm()
        if after!=snapshot:raise Rejected('FPM_REFUSED')
        receipt['stage']='FASTCGI_END';request.finish()
        kernel.check()
        receipt.update(status='OBSERVED',stage='COMPLETE',reason=None)
    except Exception as error:
        receipt['reason']=reason(error)
        # Metadata never survives a failed final stability/transport check.
        receipt['metadata']=None;receipt['configured_runtime']='NOT_ESTABLISHED'
    finally:
        if lock is not None:
            try:os.close(lock)
            except Exception:receipt.update(status='BLOCKED',reason='CHANNEL_REFUSED',metadata=None,configured_runtime='NOT_ESTABLISHED')
        for resource in (connection,listener,request):
            if resource is not None:
                try:resource.close()
                except Exception:
                    receipt.update(status='BLOCKED',reason='CHANNEL_REFUSED',metadata=None,configured_runtime='NOT_ESTABLISHED')
    return receipt
