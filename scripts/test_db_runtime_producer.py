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

from test_db_runtime_protocol import VERSION, Rejected, Wire, context_digest, control_context_digest
from test_db_runtime_fastcgi import FastCGI
from test_db_runtime_kernel import Kernel
from test_db_runtime_preentry import observe as pre_entry
from test_db_runtime_staging_view import verify as staging_view
from test_db_runtime_control_contract import staging_valid

from test_db_runtime_control_contract import STAGES, REASONS, FD_REASONS


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
                configured_runtime='NOT_ESTABLISHED',dependency_trust='INSTALLED_PHP_AND_VENDOR_NOT_ATTESTED',
                pre_entry='NOT_ESTABLISHED',effective_ini_selection='NOT_ATTESTED',worker_memory='NOT_ATTESTED',
                fastcgi_state='NOT_SENT',
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
    receipt['sql']='AUTHORIZED_NOT_CONFIRMED';wire.send('ROOT',4,{'stage':'SELECT'})
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
    # Historical private publisher context remains a different scope. Without
    # the new capsule's fresh staging it cannot start this diagnostic.
    return _collect(context,context_digest,None,None)


def collect_control(context, staging, deadline_ns):
    return _collect(context,control_context_digest,staging,deadline_ns)


def _collect(context,digest_for,staging,deadline_ns):
    receipt=closed();listener=request=connection=None;lock=None
    try:
        digest_for(context)
        if sys.platform!='linux' or os.geteuid()!=0:raise Rejected('ROOT_LINUX_REQUIRED')
        if not staging_valid(staging) or type(deadline_ns) is not int:raise Rejected('STAGING_VIEW_REFUSED')
        deadline=min(time.monotonic()+3,deadline_ns/1e9)
        if deadline<=time.monotonic():raise Rejected('DEADLINE')
        kernel=Kernel(deadline)
        receipt['stage']='FPM_BEFORE';lock=kernel.ns['_manifest_lock'](deadline);snapshot,_=kernel.fpm()
        receipt['stage']='PRE_ENTRY';ini_before=pre_entry(kernel,snapshot);entry_before=staging_view(staging,kernel,snapshot);receipt['pre_entry']='OBSERVED'
        publisher=pwd.getpwnam('jsm').pw_uid
        if not 0<publisher<=2147483647:raise Rejected('FPM_REFUSED')
        nonce,channel=secrets.token_hex(16),secrets.token_hex(16)
        digest=digest_for(context)
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        listener.bind('\0jsm-db-2760-'+channel);listener.listen(1)
        receipt['stage']='CHANNEL'
        def fpm_peer(stream):
            pid,uid,gid=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if pid!=snapshot[0]['php']['pid'] or uid!=0:raise Rejected('FPM_REFUSED')
        request=FastCGI(nonce,digest,channel,deadline,staging,peer_check=fpm_peer,
                        on_send=lambda:receipt.update(fastcgi_state='UNCONFIRMED'))
        listener.settimeout(min(.75,max(0,deadline-time.monotonic())))
        connection,_=listener.accept()
        worker=worker_from_peer(snapshot,struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)),kernel,deadline)
        wire=Wire(connection,nonce,digest,deadline)
        dialogue(wire,kernel,worker,publisher,receipt)
        receipt['stage']='FPM_AFTER'
        after,_=kernel.fpm()
        if after!=snapshot:raise Rejected('FPM_REFUSED')
        receipt['stage']='PRE_ENTRY'
        if pre_entry(kernel,after)!=ini_before:raise Rejected('PRE_ENTRY_CHANGED')
        if staging_view(staging,kernel,after)!=entry_before:raise Rejected('STAGING_VIEW_REFUSED')
        receipt['stage']='FASTCGI_END';request.finish();receipt['fastcgi_state']='FINISHED'
        kernel.check()
        receipt.update(status='OBSERVED',stage='COMPLETE',reason=None)
    except Exception as error:
        receipt['reason']=reason(error)
        # Metadata never survives a failed final stability/transport check.
        receipt['metadata']=None;receipt['configured_runtime']='NOT_ESTABLISHED';receipt['pre_entry']='NOT_ESTABLISHED'
    finally:
        if connection is not None:
            try:connection.close()
            except OSError:pass
        if request is not None:
            try:request.finish()
            except Exception:pass
            if request.done:receipt['fastcgi_state']='FINISHED'
        if lock is not None:
            try:os.close(lock)
            except Exception:receipt.update(status='BLOCKED',reason='CHANNEL_REFUSED',metadata=None,configured_runtime='NOT_ESTABLISHED')
        for resource in (connection,listener,request):
            if resource is not None:
                try:resource.close()
                except Exception:
                    receipt.update(status='BLOCKED',reason='CHANNEL_REFUSED',metadata=None,configured_runtime='NOT_ESTABLISHED')
    return receipt
